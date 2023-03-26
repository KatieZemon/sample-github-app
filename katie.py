import asyncio

import aiohttp
import os
from gidgethub.aiohttp import GitHubAPI

from gidgethub import sansio


async def post_comment_on_pull_request():
    print("Hello World")

    # post_comment_on_pull_request(owner, repo, pull_request_number, comment, token):
    # Create an instance of the GitHub API client
    owner = 'KatieZemon'
    repo = 'sampleOpsRepo'
    pull_request_number = '1'
    url = f"/repos/{owner}/{repo}/issues/{pull_request_number}/comments"

    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session,
                       owner,
                       oauth_token=os.getenv("GH_AUTH"))
        response = await gh.post(
            url,
            data={
                'body': 'Great Stuff!',
            }
        )

# Example usage:
loop = asyncio.get_event_loop()
loop.run_until_complete(post_comment_on_pull_request())

# async def main():
#     async with aiohttp.ClientSession() as session:
#         owner = 'KatieZemon'
#         repo = 'KatieZemon/sampleOpsRepo'
#         pull_request_number='1'
#         url = f"/repos/{owner}/{repo}/issues/{pull_request_number}/comments"
#
#         gh = GitHubAPI(session,
#                        owner,
#                        oauth_token=os.getenv("GH_AUTH"))
#         response = await_gh.post(
#             url,
#             data={
#                 'body': 'Great Stuff!',
#                 'commit_id': 'c625413bba4378e472c8bbdc1b08db931f761a02',
#                 'path': 'file1.txt',
#                 'line':'1'
#             }
#         )
#         print(f"Issue created at {response['html_url']}")
# asyncio.run(main())
