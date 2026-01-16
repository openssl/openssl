# Grokipedia - 2012 Aurora Theater Shooting

This repository contains the configuration and integration for the Grokipedia page about the 2012 Aurora Theater Shooting.

## Project Information

- **Official Live URL**: https://grokipedia.com/page/2012_Aurora_shooting
- **Team ID**: e97e6a25-cade-442f-9415-04b7ebae2898

## Grok API Integration

This project integrates with the x.ai Grok API for AI-powered content generation and analysis.

### API Configuration

The API configuration is stored in `grokipedia.config.json`:

- **Provider**: x.ai
- **Endpoint**: https://api.x.ai/v1/chat/completions
- **Model**: grok-4-latest
- **Authentication**: Bearer token

### Setup

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your x.ai API key:
   ```
   XAI_API_KEY=xai-your-actual-api-key-here
   ```

3. Test the API integration:
   ```bash
   python3 test_grok_api.py
   ```

### API Usage Example

Here's a sample cURL command to test the Grok API:

```bash
curl https://api.x.ai/v1/chat/completions \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $XAI_API_KEY" \
    -d '{
      "messages": [
        {
          "role": "system",
          "content": "You are a test assistant."
        },
        {
          "role": "user",
          "content": "Testing. Just say hi and hello world and nothing else."
        }
      ],
      "model": "grok-4-latest",
      "stream": false,
      "temperature": 0
    }'
```

### Configuration Files

- `grokipedia.config.json` - Main configuration file with project and API settings
- `.env.example` - Template for environment variables
- `test_grok_api.py` - Python script to test API integration

## TODO

- Create `resume.pdf` using LaTeX

## Security Notes

- Never commit your actual API key to the repository
- The `.env` file is ignored by git (see `.gitignore`)
- Store sensitive credentials in environment variables

## License

See [LICENSE.txt](LICENSE.txt) for license information.
