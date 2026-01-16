#!/usr/bin/env python3
"""
Grokipedia API Integration
Demonstrates integration with x.ai Grok API
"""

import json
import os
import sys

def load_config():
    """Load configuration from grokipedia.config.json"""
    config_path = os.path.join(os.path.dirname(__file__), 'grokipedia.config.json')
    with open(config_path, 'r') as f:
        return json.load(f)

def test_grok_api():
    """Test the Grok API integration"""
    config = load_config()
    
    print("=== Grokipedia Configuration ===")
    print(f"Project: {config['project']['name']}")
    print(f"Official URL: {config['project']['officialUrl']}")
    print(f"Team ID: {config['project']['teamId']}")
    print()
    print("=== API Configuration ===")
    print(f"Provider: {config['api']['provider']}")
    print(f"Endpoint: {config['api']['endpoint']}")
    print(f"Model: {config['api']['model']}")
    print()
    
    # Get API key from environment
    api_key = os.environ.get(config['api']['authentication']['tokenEnvVar'])
    
    if not api_key:
        print(f"Error: {config['api']['authentication']['tokenEnvVar']} environment variable not set")
        print("Please set your x.ai API key in the environment or .env file")
        return 1
    
    print("API key is configured")
    print()
    print("=== Sample cURL Command ===")
    print(f"""curl {config['api']['endpoint']} \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $XAI_API_KEY" \\
    -d '{{
      "messages": [
        {{
          "role": "system",
          "content": "You are a test assistant."
        }},
        {{
          "role": "user",
          "content": "Testing. Just say hi and hello world and nothing else."
        }}
      ],
      "model": "{config['api']['model']}",
      "stream": {str(config['api']['defaultParameters']['stream']).lower()},
      "temperature": {config['api']['defaultParameters']['temperature']}
    }}'""")
    
    return 0

if __name__ == '__main__':
    sys.exit(test_grok_api())
