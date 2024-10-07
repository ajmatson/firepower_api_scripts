#!/usr/bin/env python3

import requests
import json
from getpass import getpass
import os
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# FMC Configurations
fmc_ips = ["FMC_IP_URL"]

# Function to obtain authentication token with retry on failure
def get_auth_token(fmc_ip, username, password):
    url = f"https://{fmc_ip}/api/fmc_platform/v1/auth/generatetoken"
    headers = {"Content-Type": "application/json"}

    while True:
        response = requests.post(url, headers=headers, auth=(username, password), verify=False)
        if response.status_code == 204:
            auth_token = response.headers.get("X-auth-access-token")
            return auth_token
        else:
            print(f"Failed to obtain token from FMC {fmc_ip}: {response.status_code}. Please check your username or password.")
            username = input("Re-enter FMC username: ")
            password = getpass("Re-enter FMC password: ")

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
    else:
        print(f"Failed to fetch network groups from FMC {fmc_ip}: {response.status_code}, {response.text}")
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
def add_object_to_group(fmc_ip, auth_token, group_id, object_name, object_id, group_name):
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
        print(f"Successfully added {object_name} to {group_name} group on FMC {fmc_ip}")
    elif response.status_code == 422 and "Unprocessable Entity" in response.text:
        print(f"Object {object_name} is already in the {group_name} group on FMC {fmc_ip}.")
    else:
        print(f"Failed to add {object_name} to {group_name} group on FMC {fmc_ip}: {response.status_code}, {response.text}")

# Function to create a host object in FMC and add it to the group
def create_and_add_host_object(fmc_ip, auth_token, ip_address, description, group_id, group_name):
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
            print(f"Failed to create host object for {ip_address} on FMC {fmc_ip}: {response.status_code}, {response.text}")
            return

    # Check if the object is already in the group
    if not check_object_in_group(fmc_ip, auth_token, group_id, object_id):
        # Add the object to the group
        add_object_to_group(fmc_ip, auth_token, group_id, object_name, object_id, group_name)
    else:
        print(f"Object {object_name} is already in the {group_name} group on FMC {fmc_ip}.")

# Correct deployment function
def deploy_configuration(fmc_ip, auth_token):
    # Step 1: Retrieve deployable devices
    deployable_url = f"https://{fmc_ip}/api/fmc_config/v1/domain/default/deployment/deployabledevices"
    headers = {
        "Content-Type": "application/json",
        "X-auth-access-token": auth_token
    }
    deployable_response = requests.get(deployable_url, headers=headers, verify=False)

    if deployable_response.status_code == 200:
        deployable_devices = deployable_response.json().get("items", [])
        device_ids = [device["device"]["id"] for device in deployable_devices if device.get("canBeDeployed")]

        # Step 2: If there are devices, deploy the configuration
        if device_ids:
            deploy_url = f"https://{fmc_ip}/api/fmc_config/v1/domain/default/deployment/deploymentrequests"
            deploy_payload = {
                "type": "DeploymentRequest",
                "forceDeploy": True,
                "ignoreWarning": True,
                "version": deployable_devices[0]["version"],
                "deviceList": device_ids
            }
            deploy_response = requests.post(deploy_url, headers=headers, json=deploy_payload, verify=False)
            if deploy_response.status_code in [200, 201]:
                print(f"Successfully deployed configuration to devices on FMC {fmc_ip}")
            else:
                print(f"Failed to deploy configuration on FMC {fmc_ip}: {deploy_response.status_code}, {deploy_response.text}")
        else:
            print(f"No devices require deployment on FMC {fmc_ip}")
    else:
        print(f"Failed to retrieve deployable devices from FMC {fmc_ip}: {deployable_response.status_code}, {deployable_response.text}")

# Main script logic
def main():
    os.system('cls' if os.name == 'nt' else 'clear')

    # Prompt for username and password
    print("#######################################################################")
    print("# This script is designed to assist Cisco FMC admins to quickly       #")
    print("# add IP addresses to an object and then add those objects to a       #")
    print("# group already in the FMC. This reduces time to add objects daily.   #")
    print("#                                                                     #")
    print("# Created by Alan Matson (ajmatson @ gmail)                           #")
    print("# Date: 10/04/2024     v: 1.9b                                        #")
    print("#                                                                     #")
    print("#######################################################################")
    print("                                                                       ")
    username = input("Enter FMC username: ")
    password = getpass("Enter FMC password: ")

    # Store tokens for both FMCs
    auth_tokens = {}

    # Loop over each FMC IP and authenticate for each one
    for fmc_ip in fmc_ips:
        try:
            auth_token = get_auth_token(fmc_ip, username, password)
            auth_tokens[fmc_ip] = auth_token
        except Exception as e:
            print(f"Error connecting to FMC {fmc_ip}: {e}")
            sys.exit(1)  # Exit if unable to authenticate with an FMC

    # Prompt for group name (default to Blocked_Attackers)
    group_name = input("Enter the name of the group (press Enter to use 'Blocked_Attackers'): ")
    if not group_name:
        group_name = "Blocked_Attackers"

    # Prompt for comma-separated list of IPs
    ip_addresses = input("Enter a comma-separated list of IP addresses: ").split(',')

    # Prompt for description
    description = input("Enter a description for the objects: ")

    # Loop over each FMC IP to process the objects
    for fmc_ip in fmc_ips:
        try:
            auth_token = auth_tokens[fmc_ip]

            # Retrieve the ID of the user-provided or default group
            group_id = get_group_id(fmc_ip, auth_token, group_name)
            if not group_id:
                print(f"Error: The group {group_name} does not exist on FMC {fmc_ip}.")
                continue

            # Create or check the existence of a host object for each IP address and add it to the group
            for ip_address in ip_addresses:
                create_and_add_host_object(fmc_ip, auth_token, ip_address.strip(), description, group_id, group_name)

        except Exception as e:
            print(f"Error processing FMC {fmc_ip}: {e}")

    # Prompt for deployment
    deploy = input("Do you want to deploy the configuration? (Yes/No, default is No): ").lower()

    if deploy in ["yes", "y"]:
        # Loop over each FMC IP to deploy the configuration
        for fmc_ip in fmc_ips:
            try:
                deploy_configuration(fmc_ip, auth_tokens[fmc_ip])
            except Exception as e:
                print(f"Error deploying configuration to FMC {fmc_ip}: {e}")
    else:
        print("Configuration changes are not deployed.")

if __name__ == "__main__":
    main()
