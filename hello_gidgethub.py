import asyncio
import json
import random
import logging
import aiohttp
from aiohttp import web
from gidgethub import routing
from gidgethub import sansio
import gidgethub
from gidgethub.aiohttp import GitHubAPI

import jwt_generator

router = routing.Router()

logging.basicConfig(level=logging.DEBUG)
LOGGER = logging.getLogger(__name__)
SNOW_GATE_PASS = False


async def list_commands(event: sansio.Event):
    comment_text = '''
**Commands**
- /help - Lists all available commands
- /snow - Runs the servicenow scan
- /twistlock - Runs the twistlock check
- /rerun - Runs all the checks
    '''
    LOGGER.debug("Listing out commands")
    await post_comment_on_pull_request(event.data['repository']['full_name'],
                                       event.data['issue']['number'],
                                       event.data['installation']['id'],
                                       comment_text)


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


async def create_check(repo_full_name: str, installation_id: int, name: str, sha: str):
    url = f"/repos/{repo_full_name}/check-runs"

    data = {
        "name": name,
        "head_sha": sha,
        "status": "queued"
    }

    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        response = await gh.post(
            url,
            oauth_token=access_token,
            data=data
        )
        LOGGER.debug(f'Check created with response {json.dumps(response)}')
        check_id = str(response['id'])
        return check_id


async def update_check(check_id, data, repo_full_name: str, installation_id: int):
    url = f"/repos/{repo_full_name}/check-runs/{check_id}"
    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        response = await gh.patch(
            url,
            oauth_token=access_token,
            data=data
        )
    return response


async def run_snow_gate(repo_full_name: str, installation_id: int, sha: str):
    check_id = await create_check(repo_full_name, installation_id, "ServiceNow Check", sha)
    # UPDATE CHECK Status to In Progress
    data = {
        "status": "in_progress"
    }
    await update_check(check_id, data, repo_full_name, installation_id)

    # At this point we would Execute the ServiceNow check and get a response
    LOGGER.debug("Checking ServiceNow Status...")
    await asyncio.sleep(2)  # pretend it takes several seconds to call snow and get a response

    snow_check_passed = SNOW_GATE_PASS

    if snow_check_passed:
        LOGGER.debug("Snow check passed")

        # UPDATE Check status to Complete
        data = {
            "status": "completed",
            "conclusion": "success",
            "details_url": "https://docs.servicenow.com",
            "output": {"title": "ServiceNow Status Report",
                       "summary": "The Change is approved for implementation\n- **Change Start Time:** "
                                  "2023-04-02T04:00:00Z\n- **Change End Time:** 2023-04-27T09:00:00Z\n- **Change "
                                  "Description:** Add 3 unicorns to the awesome-bot application\n\n![Unicorn Image]("
                                  "https://img.favpng.com/0/5/1/unicorn-reem-logo-github-being-png-favpng"
                                  "-0yfM63Wd1MM7KKcJsBhwBhHHq.jpg)",
                       "text":
                       # language=Markdown
                           "A detailed summary output of the ServiceNow call is below:\n\n```json\n{\n  \"result\": {"
                           "\n  \"sys_id\": \"1234567890abcdef\",\n    \"change_number\": \"CHG00001234\","
                           "\n    \"state\": \"implement\",\n    \"short_description\": \"Add 3 unicorns to the "
                           "awesome-bot application\"\n  }\n}\n```"
                       }
        }
    else:
        LOGGER.debug("Snow check failed")
        data = {
            "status": "completed",
            "conclusion": "failure",
            "details_url": "https://docs.servicenow.com",
            "output": {"title": "ServiceNow Status Report",
                       "summary": "ServiceNow check failed. The change approvals were revoked, please re-approve the "
                                  "change. \n![]("
                                  "https://images.squarespace-cdn.com/content/v1/50ba24bfe4b0566a5b11d671"
                                  "/1374432570435-JXLFQBA0B2NXGE29Z5QY/humor-failure-funny+%2820%29.jpg)",
                       "text": "A detailed summary output of the ServiceNow call is below:\n\n```json\n{\n  "
                               "\"result\": {\n  \"sys_id\": \"1234567890abcdef\",\n    \"change_number\": "
                               "\"CHG00001234\",\n    \"state\": \"revoked\",\n    \"short_description\": \"Add 3 "
                               "unicorns to the awesome-bot application\",\n    \"approval_history\": [\n        {\n  "
                               "          \"name\": \"John Doe\",\n            \"date\": \"2023-03-25T15:20:00Z\","
                               "\n            \"state\": \"approved\"\n        },\n        {\n            \"name\": "
                               "\"Jane Smith\",\n            \"date\": \"2023-03-27T10:05:00Z\",\n            "
                               "\"state\": \"revoked\"\n        }\n    ]\n  }\n}\n```"
                       }
        }

    response = await update_check(check_id, data, repo_full_name, installation_id)
    LOGGER.debug('Snow Check updated with response ' + json.dumps(response))


async def run_twistlock_gate(repo_full_name: str, installation_id: int, sha: str):
    check_id = await create_check(repo_full_name, installation_id, "Twistlock Check", sha)
    # UPDATE CHECK Status to In Progress
    data = {
        "status": "in_progress"
    }
    response = await update_check(check_id, data, repo_full_name, installation_id)
    LOGGER.debug("Updated twistlock check status to 'In Progress' " + json.dumps(response))

    # At this point, we would run the twistlock check
    LOGGER.debug("Running Twistlock Scan...")
    await asyncio.sleep(4)  # Pretend twistlock scan took a number of seconds

    twistlock_passed = random.choices([True, False], weights=[0.9, 0.1])[0]

    if twistlock_passed:
        LOGGER.debug("Twistlock Passed")
        data = {
            "status": "completed",
            "conclusion": "success",
            "details_url": "https://nvd.nist.gov",
            "output": {
                "title": "Twistlock Vulnerability Report",
                "summary": "The image scan completed successfully with no vulnerabilities found.\n ![Twistlock Logo]("
                           "https://upload.wikimedia.org/wikipedia/commons/8/89/Twistlock_Logo.png?20180312162553)",
                "text": "A detailed summary output of the Twistlock scan is below:\n\n```\nScanning image: "
                        "myapp:latest\n\nNo vulnerabilities found.\n\nScan completed with 0 vulnerabilities found.\n```"
            }
        }
    else:
        data = {
            "status": "completed",
            "conclusion": "failure",
            "details_url": "https://nvd.nist.gov",
            "output": {"title": "Twistlock Vulnerability Report",
                       "summary": "The image scan failed due to vulnerabilities found. Please see detailed output for "
                                  "more information.\n ![]("
                                  "https://m100group.files.wordpress.com/2012/05/failure-8.jpg)",
                       "text": "A detailed summary output of the Twistlock scan is below:\n\n```\nScanning image: "
                               "myapp:latest\n\n[ERROR] High severity vulnerability found: CVE-2022-1234\nPackage: "
                               "openssl\nVersion: 1.0.2t-r0\n\n[ERROR] Critical severity vulnerability found: "
                               "CVE-2022-5678\nPackage: bash\nVersion: 4.3.42-r3\n\n[ERROR] Medium severity "
                               "vulnerability found: CVE-2022-9012\nPackage: openssh\nVersion: 7.5_p1-r3\n\nScan "
                               "completed with 3 vulnerabilities found.\n```",
                       }
        }

    response = await update_check(check_id, data, repo_full_name, installation_id)
    LOGGER.debug('Twistlock Check Updated with response ' + json.dumps(response))


async def produce_access_token(gh: GitHubAPI, install_id: int):
    jwt = jwt_generator.generate()
    url = f"/app/installations/{install_id}/access_tokens"
    response = await gh.post(url, jwt=jwt, data=None)
    return response['token']


async def get_sha_with_pr_url(pr_url: str, repo_full_name: str, installation_id: int):
    if "/pull/" in pr_url:
        pr_number = pr_url.split("/pull/")[1]
    else:
        pr_number = pr_url.split("/pulls/")[1]

    url = f"/repos/{repo_full_name}/pulls/{pr_number}"

    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        response = await gh.getitem(
            url,
            oauth_token=access_token,
        )
        sha = response['head']['sha']

    return sha


async def get_sha_with_check_id(check_id: str, repo_full_name: str, installation_id: int):
    url = f"/repos/{repo_full_name}/check-runs/{check_id}"
    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        response = await gh.getitem(
            url,
            oauth_token=access_token
        )
        sha = response['head_sha']
        return sha


async def snow_handler(request: aiohttp.web.Request):
    body = json.loads(await request.read())
    pr_url: str = body['pull_request_url']
    install_id: int = body['installation_id']
    repo_full_name: str = pr_url.split("github.com/")[1].split("/pull/")[0]
    sha: str = await get_sha_with_pr_url(pr_url, repo_full_name, install_id)
    await run_snow_gate(repo_full_name, install_id, sha)
    return web.Response(status=200)


@router.register(event_type="issue_comment", action="created")
async def issue_comment_created(event: sansio.Event):
    comment_text: str = event.data['comment']['body']
    comment_text = comment_text.strip()

    if comment_text.startswith(('/snow', '/twistlock', '/rerun', '/help')):
        repo_full_name: str = event.data['repository']['full_name']
        install_id: int = event.data['installation']['id']
        pr_url = event.data['issue']['pull_request']['url']

        sha = await get_sha_with_pr_url(pr_url, repo_full_name, install_id)

        if comment_text.startswith('/snow'):
            await run_snow_gate(repo_full_name, install_id, sha)
        elif comment_text.startswith('/twistlock'):
            await run_twistlock_gate(repo_full_name, install_id, sha)
        elif comment_text.startswith('/rerun'):
            await asyncio.gather(run_snow_gate(repo_full_name, install_id, sha),
                                 run_twistlock_gate(repo_full_name, install_id, sha))
        elif comment_text.startswith('/help'):
            await list_commands(event)


# Whenever you click "rerun" on a failed check, call this code
@router.register(event_type="check_run", action="rerequested")
async def rerun_check(event: sansio.Event):
    check_name = event.data['check_run']['name']
    check_id = event.data['check_run']['id']
    repo_full_name: str = event.data['repository']['full_name']
    install_id: int = event.data['installation']['id']
    sha: str = await get_sha_with_check_id(check_id, repo_full_name, install_id)

    if "Twistlock" in check_name:
        await run_twistlock_gate(repo_full_name, install_id, sha)
    elif "ServiceNow" in check_name:
        await run_snow_gate(repo_full_name, install_id, sha)


# When a pull request is reopened, run all gates
@router.register(event_type="pull_request", action="reopened")
async def opened_pr(event: sansio.Event):
    repo_full_name = event.data['repository']['full_name']
    install_id = event.data['installation']['id']
    sha = event.data['pull_request']['head']['sha']
    await asyncio.gather(run_snow_gate(repo_full_name, install_id, sha),
                         run_twistlock_gate(repo_full_name, install_id, sha))


# Whenever you click "rerun all checks" button on the "Checks" tab, rerun all gates
# Whenever you open a PR, GitHub will send event check_squite with action=requested
@router.register(event_type="check_suite", action="rerequested")
@router.register(event_type="check_suite", action="requested")
async def check_suite_requested(event: sansio.Event):
    repo_full_name = event.data['repository']['full_name']
    install_id = event.data['installation']['id']
    sha = event.data['check_suite']['head_sha']
    await asyncio.gather(run_snow_gate(repo_full_name, install_id, sha),
                         run_twistlock_gate(repo_full_name, install_id, sha))


async def get_required_status_checks(repo_full_name: str, branch: str, installation_id: int):
    url = f"/repos/{repo_full_name}/branches/{branch}/protection/required_status_checks"

    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        response = await gh.get(
            url,
            oauth_token=access_token,
        )

    return response


# TODO
# Whenever a pull request is opened, make sure all checks exist
@router.register("pull_request", action="opened")
async def opened_pr(event: sansio.Event):
    repo_full_name = event.data['repository']['full_name']
    branch = event.data['pull_request']['head']['ref']
    install_id = event.data['installation']['id']

    required_checks = await get_required_status_checks(repo_full_name, branch, install_id)


async def get_branch_protection(repo_full_name: str, installation_id: int):
    url = f"/repos/{repo_full_name}/branches/main/protection"
    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        try:
            response = await gh.getitem(
                url,
                oauth_token=access_token
            )
        except gidgethub.BadRequest as e:
            LOGGER.debug("Main Branch is not protected. Need to add a main branch protection")
            return None

    return response


async def update_branch_protection(repo_full_name: str, installation_id: int):
    url = f"/repos/{repo_full_name}/branches/main/protection"
    async with aiohttp.ClientSession() as session:
        gh = GitHubAPI(session, "katiesamplebot")
        access_token = await produce_access_token(gh, installation_id)
        response = await gh.put(
            url,
            oauth_token=access_token,
            data = {
                'required_status_checks': {
                    'strict': True,
                    'contexts': [
                        'ServiceNow Check',
                        'Twistlock Check'
                    ]
                },
                'enforce_admins': True,
                'restrictions': None,
                'required_pull_request_reviews': {
                    'required_approving_review_count': 1
                }
            }
        )
    return response


def is_branch_protection_valid(response):
    is_valid = False
    if 'required_pull_request_reviews' in response and 'required_status_checks' in response:
        checks = response['required_status_checks']['checks']
        if len(checks) >= 2 and \
            any(check['context'] == 'ServiceNow Check' for check in checks) and \
            any(check['context'] == 'Twistlock Check' for check in checks) and \
            response['required_pull_request_reviews']['required_approving_review_count'] >= 1:
            is_valid = True
    return is_valid


# If someone modifies the branch protection rule or removes a required check, add it back
@router.register(event_type="branch_protection_rule", action="deleted")
@router.register(event_type="branch_protection_rule", action="edited")
@router.register(event_type="branch_protection_rule", action="created")
async def handle_branch_protection_rule_event(event: sansio.Event):
    repo_full_name = event.data['repository']['full_name']
    installation_id = event.data['installation']['id']
    branch_protection = await get_branch_protection(repo_full_name, installation_id)
    if branch_protection is None:
        LOGGER.debug("There is no branch protection on main")
        # TBD create new branch protection
    elif is_branch_protection_valid(branch_protection):
        LOGGER.debug("Branch protection looks good!")
    else:
        LOGGER.debug("Branch protection is invalid. Updating it")
        await update_branch_protection(repo_full_name, installation_id)


async def gh_event_handler(request: aiohttp.web.Request):
    body = await request.read()
    event = sansio.Event.from_http(request.headers, body)
    if event.event:
        await router.dispatch(event)
        return web.Response(status=200)
    else:
        return web.Response(status=404)


if __name__ == "__main__":
    app = web.Application()
    app.router.add_post("/mywebhook", gh_event_handler)
    app.router.add_post("/handle_snow_request", snow_handler)
    web.run_app(app, port=9684)
