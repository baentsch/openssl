# Sole goal is to report KPIs as proposed by @mattcaswell in https://github.com/openssl/project/issues/1374

CHECK_PERIOD=365 #days
CNOBACK=0
ONOBACK=0
NOBACK=0

# enabling this increases script runtime about 100x but honors proposed use of "backlog" label:
checklabels = False

PROJECT="openssl/openssl"

import requests
import os
import sys
from datetime import datetime, date, time, timezone, timedelta

if "GHTOKEN" not in os.environ:
    print("Warning: GHTOKEN not set: Low rate limit!")
    headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
else:
    headers = {'Authorization': 'Bearer ' + os.environ["GHTOKEN"], 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}

def getnextlink(headers):
    if "link" in headers.keys():
        nxt = headers["link"].find(">; rel=\"next\"")
        if (nxt > 0):
           # starting point is preceding https:
           start = headers["link"].rfind("https:", 0, nxt) 
           if start < 0:
               print("Unexpected failure to locate next page start URL in " + headers["link"])
               return ""
           return headers["link"][start:nxt]
    return ""

now = datetime.now(timezone.utc)
endcheckdate = now - timedelta(days = CHECK_PERIOD)

# iterate through all open issues -- these include PRs

# maximum number for API: 100; less is possible but less efficient (counting towards rate limit)
next = 'https://api.github.com/repos/'+PROJECT+'/issues?state=all&per_page=100'
issues = 0
prs=0
while (next != ""):
  r = requests.get(next, headers=headers)
  if r.status_code != 200:
     print("Failed to get next issue batch. Aborting.")
     break
  rh = r.headers
  if "X-RateLimit-Remaining" in rh.keys():
     if int(rh["X-RateLimit-Remaining"]) < 100:
         print("Warning: Rate limit remaining: " + rh["X-RateLimit-Remaining"])
  next = getnextlink(rh)
  for issue in r.json():
     issues+=1
     inr = issue["number"]
     ispr = "pull_request" in issue.keys()
     isopen = issue["state"] == "open"
     dt = datetime.strptime(issue["created_at"], "%Y-%m-%dT%H:%M:%SZ")

     if ispr:
        prs+=1

     dtd = now-dt.replace(tzinfo=timezone.utc)

     if checklabels:
        # KPIS seem to require label check ("backlog") -- but this adds a 100x of queries, so switching off by default for now:
        # also check labels (https://docs.github.com/en/rest/issues/labels?apiVersion=2022-11-28#list-labels-for-an-issue)
        reqlabels = "https://api.github.com/repos/"+PROJECT+"/issues/"+str(inr)+"/labels"
        lresp = requests.get(reqlabels, headers=headers)
        if lresp.status_code != 200:
           print("Failed to get labels for issue %d. Aborting check." % (inr))
           break
        # don't assume pagination to be an issue (TBC)
        backlog = 0
        for label in lresp.json():
            if (label["name"].find("backlog") == 0):
               backlog = 1
     else: # assume no backlog
        backlog = 0

     if backlog == 0 and not ispr:
          if isopen:
             if endcheckdate.timestamp() < dt.timestamp():
                ONOBACK+=1
                NOBACK+=1
          elif issue["state"] == "closed":
             alreadycounted=False
             if endcheckdate.timestamp() < dt.timestamp():
                ONOBACK+=1
                NOBACK+=1
                alreadycounted=True
             cdt = datetime.strptime(issue["closed_at"], "%Y-%m-%dT%H:%M:%SZ")
             if endcheckdate.timestamp() < cdt.timestamp():
                CNOBACK+=1
                if not alreadycounted: NOBACK+=1
          else:
             print("Issue %d in state %s. Don't know how to count." % (inr, issue["state"]))

print("%d issues overall" % (issues))
print("%d PRs overall" % (prs))
print("KPIs: On %d overall issues in check period:" %(NOBACK))
print("  %d opened" % (ONOBACK))
print("  %d closed" % (CNOBACK))
