#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script to add host objects to FMC blocklist and group.
This script interacts with multiple FMCs to manage network objects and groups.

Author: Your Name
Date: 2024-08-23
Version: 1.0

Default Configuration:
- FMC IPs: ["1.1.1.1", "2.2.2.2"]
- Default Group Name: "Blocked_Attackers"
- Default Host File: "hosts.txt"
"""

import requests
import json
import argparse
from getpass import getpass

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Default FMC Configuration
fmc_ips = ["1.1.1.1", "2.2.2.2"]
group_name = "Blocked_Attackers"
filename = "hosts.txt"

# Function to obtain authentication token
def get_auth_token(fmc_ip, username, password):
    url = f"https://{fmc_ip}/api/fmc_platform/v1/auth/generatetoken"
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, headers=headers, auth=(username, password), verify=False)

    if response.status_code == 204:
        auth_token = response.headers.get("X-auth-access-token")
        return auth_token
    else:
        raise Exception(f"Failed to obtain token from FMC {fmc_ip}: {response.status_code}")

# Function to retrieve the ID of a network group by name
def get_group_id(fmc_ip, auth_token, group_name):
    url = f"https://{fmc_ip}/api/fmc_config/v1/domain/default/object/networkgroups"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": auth_token
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        groups = response.json().get("items", [])
        for group in groups:
            if group["name"] == group_name:
                return group["id"]
    return None

# Function to check if a host object exists in FMC
def check_host_object_exists(fmc_ip, auth_token, object_name):
    url = f"https://{fmc_ip}/api/fmc_config/v1/domain/default/object/hosts"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": auth_token
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        objects = response.json().get("items", [])
        for obj in objects:
            if obj["name"] == object_name:
                return obj["id"]
    return None

# Function to check if a host object is already in the group
def check_object_in_group(fmc_ip, auth_token, group_id, object_id):
    url = f"https://{fmc_ip}/api/fmc_config/v1/domain/default/object/networkgroups/{group_id}"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": auth_token
    }
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        group = response.json()
        for obj in group.get("objects", []):
            if obj["id"] == object_id:
                return True
    return False

# Function to add a host object to the group
def add_object_to_group(fmc_ip, auth_token, group_id, object_name, object_id):
    url = f"https://{fmc_ip}/api/fmc_config/v1/domain/default/object/networkgroups/{group_id}"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": auth_token
    }

    # Retrieve the current group data
    response = requests.get(url, headers=headers, verify=False)
    group_data = response.json()

    # Add the new object to the group
    group_data["objects"].append({
        "name": object_name,
        "id": object_id,
        "type": "Host"
    })

    # Update the group with the new object
    response = requests.put(url, headers=headers, json=group_data, verify=False)

    if response.status_code in [200, 201]:
        print(f"Successfully added {object_name} to Blocked_Attackers group on FMC {fmc_ip}")
    elif response.status_code == 422 and "Unprocessable Entity" in response.text:
        # Suppress the "Unprocessable Entity" error
        print(f"Object {object_name} is already in the Blocked_Attackers group on FMC {fmc_ip}.")
    else:
        print(f"Failed to add {object_name} to Blocked_Attackers group on FMC {fmc_ip}: {response.status_code}, {response.text}")

# Function to create a host object in FMC and add it to the group
def create_and_add_host_object(fmc_ip, auth_token, ip_address, description, group_id):
    object_name = f"BL_{ip_address}"

    # Check if the host object exists
    object_id = check_host_object_exists(fmc_ip, auth_token, object_name)

    if object_id:
        print(f"Object {object_name} already exists on FMC {fmc_ip}!")
    else:
        # Create the host object if it doesn't exist
        url = f"https://{fmc_ip}/api/fmc_config/v1/domain/default/object/hosts"
        headers = {
            "Content-Type": "application/json",
            "X-auth-access-token": auth_token
        }
        payload = {
            "name": object_name,
            "type": "Host",
            "value": ip_address,
            "description": description
        }
        response = requests.post(url, headers=headers, json=payload, verify=False)

        if response.status_code in [200, 201]:
            object_id = response.json()["id"]
            print(f"Successfully created host object for {ip_address} on FMC {fmc_ip}")
        else:
            # Check if the error is because the object already exists
            if response.status_code == 400 and "already exists" in response.text:
                print(f"Object {object_name} already exists on FMC {fmc_ip}!")
            else:
                print(f"Failed to create host object for {ip_address} on FMC {fmc_ip}: {response.status_code}, {response.text}")
                return

    # Check if the object is already in the group
    if not check_object_in_group(fmc_ip, auth_token, group_id, object_id):
        # Add the object to the group
        add_object_to_group(fmc_ip, auth_token, group_id, object_name, object_id)
    else:
        print(f"Object {object_name} is already in the Blocked_Attackers group on FMC {fmc_ip}.")

# Main script logic
def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Add host objects to FMC blocklist and group")
    parser.add_argument('-d', '--description', type=str, required=True, help='Description for the host objects')
    args = parser.parse_args()

    # Prompt for username and password
    username = input("Enter FMC username: ")
    password = getpass("Enter FMC password: ")

    # Read the file and get the list of IP addresses
    try:
        with open(filename, 'r') as file:
            ip_addresses = file.read().splitlines()
    except FileNotFoundError:
        print(f"File '{filename}' not found. Please check the filename and try again.")
        return

    # Use the description provided via the command-line argument
    description = args.description

    # Loop over each FMC
    for fmc_ip in fmc_ips:
        try:
            # Get the authentication token for each FMC
            auth_token = get_auth_token(fmc_ip, username, password)

            # Retrieve the ID of the "Blocked_Attackers" group
            group_id = get_group_id(fmc_ip, auth_token, group_name)
            if not group_id:
                print(f"Error: The group '{group_name}' does not exist on FMC {fmc_ip}.")
                continue

            # Create or check the existence of a host object for each IP address and add it to the group
            for ip_address in ip_addresses:
                create_and_add_host_object(fmc_ip, auth_token, ip_address, description, group_id)

        except Exception as e:
            print(f"Error processing FMC {fmc_ip}: {e}")

if __name__ == "__main__":
    main()
current
