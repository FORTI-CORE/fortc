#!/usr/bin/env python3
"""
Resource Updater for FortiCore

This script helps to update resource files used by FortiCore.
It can add, remove, or update items in JSON resource files.
"""

import argparse
import json
import os
import sys
from typing import List, Dict, Any

# Base directory containing resources
RESOURCES_DIR = "src/resources"

def load_resource(filename: str) -> Dict[str, Any]:
    """Load a resource file from the resources directory."""
    filepath = os.path.join(RESOURCES_DIR, filename)
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: Resource file '{filename}' not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Resource file '{filename}' contains invalid JSON.")
        sys.exit(1)

def save_resource(filename: str, data: Dict[str, Any]) -> None:
    """Save data to a resource file in the resources directory."""
    filepath = os.path.join(RESOURCES_DIR, filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"Successfully updated {filename}")

def add_item(filename: str, key: str, item: str) -> None:
    """Add an item to a list in a resource file."""
    data = load_resource(filename)
    if key not in data:
        data[key] = []
    
    # Don't add duplicates
    if item not in data[key]:
        data[key].append(item)
        save_resource(filename, data)
        print(f"Added '{item}' to '{key}' in {filename}")
    else:
        print(f"Item '{item}' already exists in '{key}' in {filename}")

def remove_item(filename: str, key: str, item: str) -> None:
    """Remove an item from a list in a resource file."""
    data = load_resource(filename)
    if key not in data:
        print(f"Error: Key '{key}' not found in {filename}")
        return
    
    if item in data[key]:
        data[key].remove(item)
        save_resource(filename, data)
        print(f"Removed '{item}' from '{key}' in {filename}")
    else:
        print(f"Item '{item}' not found in '{key}' in {filename}")

def list_items(filename: str, key: str = None) -> None:
    """List all items in a resource file, optionally filtered by key."""
    data = load_resource(filename)
    
    if key:
        if key not in data:
            print(f"Error: Key '{key}' not found in {filename}")
            return
        print(f"Items in '{key}' in {filename}:")
        for item in data[key]:
            print(f"  - {item}")
    else:
        print(f"Contents of {filename}:")
        for k, v in data.items():
            print(f"Key: {k}")
            if isinstance(v, list):
                for item in v:
                    print(f"  - {item}")
            else:
                print(f"  {v}")

def add_bulk(filename: str, key: str, items_file: str) -> None:
    """Add multiple items from a text file to a list in a resource file."""
    data = load_resource(filename)
    if key not in data:
        data[key] = []
    
    try:
        with open(items_file, 'r') as f:
            items = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Error: Items file '{items_file}' not found.")
        return
    
    added_count = 0
    for item in items:
        if item not in data[key]:
            data[key].append(item)
            added_count += 1
    
    if added_count > 0:
        save_resource(filename, data)
        print(f"Added {added_count} items to '{key}' in {filename}")
    else:
        print(f"No new items added to '{key}' in {filename}")

def create_resource(filename: str, key: str) -> None:
    """Create a new resource file with an empty list for the specified key."""
    filepath = os.path.join(RESOURCES_DIR, filename)
    if os.path.exists(filepath):
        print(f"Error: Resource file '{filename}' already exists.")
        return
    
    data = {key: []}
    save_resource(filename, data)
    print(f"Created new resource file '{filename}' with empty key '{key}'")

def list_resources() -> None:
    """List all available resource files."""
    if not os.path.exists(RESOURCES_DIR):
        print(f"Error: Resources directory '{RESOURCES_DIR}' not found.")
        return
    
    files = [f for f in os.listdir(RESOURCES_DIR) if f.endswith('.json')]
    if not files:
        print("No resource files found.")
        return
    
    print("Available resource files:")
    for file in files:
        print(f"  - {file}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Update FortiCore resource files")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Add item command
    add_parser = subparsers.add_parser("add", help="Add an item to a resource file")
    add_parser.add_argument("file", help="Resource file name (e.g., 'subdomains.json')")
    add_parser.add_argument("key", help="Key in the JSON file (e.g., 'common_subdomains')")
    add_parser.add_argument("item", help="Item to add")
    
    # Remove item command
    remove_parser = subparsers.add_parser("remove", help="Remove an item from a resource file")
    remove_parser.add_argument("file", help="Resource file name")
    remove_parser.add_argument("key", help="Key in the JSON file")
    remove_parser.add_argument("item", help="Item to remove")
    
    # List items command
    list_parser = subparsers.add_parser("list", help="List items in a resource file")
    list_parser.add_argument("file", help="Resource file name")
    list_parser.add_argument("--key", help="Key to list (optional)")
    
    # Add bulk items command
    bulk_parser = subparsers.add_parser("bulk", help="Add multiple items from a file")
    bulk_parser.add_argument("file", help="Resource file name")
    bulk_parser.add_argument("key", help="Key in the JSON file")
    bulk_parser.add_argument("items_file", help="Text file with items (one per line)")
    
    # Create new resource file command
    create_parser = subparsers.add_parser("create", help="Create a new resource file")
    create_parser.add_argument("file", help="Resource file name to create")
    create_parser.add_argument("key", help="Initial key to create in the file")
    
    # List available resource files
    subparsers.add_parser("files", help="List all available resource files")
    
    args = parser.parse_args()
    
    # Create resources directory if it doesn't exist
    if not os.path.exists(RESOURCES_DIR):
        os.makedirs(RESOURCES_DIR)
    
    if args.command == "add":
        add_item(args.file, args.key, args.item)
    elif args.command == "remove":
        remove_item(args.file, args.key, args.item)
    elif args.command == "list":
        list_items(args.file, args.key)
    elif args.command == "bulk":
        add_bulk(args.file, args.key, args.items_file)
    elif args.command == "create":
        create_resource(args.file, args.key)
    elif args.command == "files":
        list_resources()
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 