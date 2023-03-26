import json
import time

import aiohttp
from aiohttp import web
from gidgethub import routing
from gidgethub import sansio
from gidgethub.aiohttp import GitHubAPI

import jwt_generator

router = routing.Router()


@router.register("pull_request", action="opened")
async def opened_pr(event: sansio.Event):
    """Mark new PRs as needing a review."""
    pull_request = event.data['pull_request']
    print(json.dumps(pull_request))


@router.register("issue_comment", action="created")
async def opened_pr(event: sansio.Event):
    """Mark new PRs as needing a review."""
    comment_text = event.data['comment']['body']
    if comment_text == '/snow':
        await post_comment_on_pull_request(event.data['repository']['full_name'],
                                           event.data['issue']['number'],
                                           event.data['installation']['id'],
                                           "ServiceNow validation looks good!")
        print('SNOW')
    elif comment_text == '/tl':
        print('TL')


async def produce_access_token(gh: GitHubAPI, install_id: int):
    jwt = jwt_generator.generate()
    time.sleep(1)
    url = f"/app/installations/{install_id}/access_tokens"
    response = await gh.post(url, jwt=jwt, data=None)
    return response['token']


async def post_comment_on_pull_request(repo_full_name: str, pull_request_number: int, installation_id: int,
                                       comment_text: str):
    url = f"/repos/{repo_full_name}/issues/{pull_request_number}/comments"

    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        await gh.post(
            url,
            oauth_token=access_token,
            data={
                'body': comment_text,
            }
        )


async def gh_event_handler(request: aiohttp.web.Request):
    body = await request.read()
    event = sansio.Event.from_http(request.headers, body)
    if event.event:
        await router.dispatch(event)
        return web.Response(status=200)
    else:
        return web.Response(status=404)


async def service_now_handler(request: aiohttp.web.Request):
    body = json.loads(await request.read())
    print(json.dumps(body))
    return web.Response(status=200)


if __name__ == "__main__":
    app = web.Application()
    app.router.add_post("/mywebhook", gh_event_handler)
    app.router.add_post("/this_is_for_service_now", service_now_handler)
    web.run_app(app, port=9684)
