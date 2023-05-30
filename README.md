Sample GitHub App
=================

## Local testing
- For local testing, store "key.pem" file in root but do not check it in
- Set environment variables
  - Store private key (`*.pem`) in `KEY_FILE_PATH`
- Execute `run.sh` to build and run your docker image
- You can test using requests.http

## More Docs
- The full list of possible events and action types: https://docs.github.com/en/webhooks-and-events/webhooks/webhook-events-and-payloads
- GitHub API Docs https://docs.github.com/en/rest/overview
- Gidgethub Getting started https://gidgethub.readthedocs.io/en/latest/
- GitHub Docs on how to create GitHub Apps: https://docs.github.com/en/apps/creating-github-apps/creating-github-apps
- Open-source Python libraries for GitHub API: https://docs.github.com/en/rest/overview/libraries?apiVersion=2022-11-28#third-party-libraries
