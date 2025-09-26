# Sole goal is to report KPIs as proposed by @mattcaswell in https://github.com/openssl/project/issues/1374

# These days are designated mass closure days for now (constant as they should never happen again):
# They will be disregarded for the KPI calculation
MCD=["2025-08-28", "2025-08-21", "2025-08-19", "2025-08-20", "2024-10-29"]

CHECK_PERIOD=365 #days

# simple counters
CNOBACK=0
ONOBACK=0
NOBACK=0

# KPI categories
CATS = ["any", "feature", "bug", "documentation"]

# dictionaries of events per day
CLOSED={}
OPENED={}
for category in CATS:
    CLOSED[category]={}
    OPENED[category]={}

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
     ds = dt.strftime("%Y-%m-%d")

     if ispr:
        prs+=1

     dtd = now-dt.replace(tzinfo=timezone.utc)

     backlog=0
     category="any"
     if not ispr:
        for label in issue["labels"]:
            if (label["name"].find("backlog") == 0):
               backlog = 1
               print("Found backlog issue %d" % (inr))
            if (label["name"].find("triaged: feature") == 0):
               category = "feature"
            elif (label["name"].find("triaged: documentation") == 0):
               category = "documentation"
            elif (label["name"].find("triaged: bug") == 0):
               category = "bug"

     if backlog == 0 and not ispr:
          if isopen:
             if endcheckdate.timestamp() < dt.timestamp():
                if ds not in OPENED[category].keys():
                    OPENED[category][ds]=0
                NOBACK+=1
                OPENED[category][ds]+=1
          elif issue["state"] == "closed":
             alreadycounted=False
             if endcheckdate.timestamp() < dt.timestamp():
                if ds not in OPENED[category].keys():
                    OPENED[category][ds]=0
                OPENED[category][ds]+=1
                NOBACK+=1
                alreadycounted=True
             cdt = datetime.strptime(issue["closed_at"], "%Y-%m-%dT%H:%M:%SZ")
             cs = cdt.strftime("%Y-%m-%d")
             if endcheckdate.timestamp() < cdt.timestamp():
                if cs not in CLOSED[category].keys():
                  CLOSED[category][cs]=0
                CLOSED[category][cs]+=1
                if not alreadycounted: NOBACK+=1
          else:
             print("Issue %d in state %s. Don't know how to count." % (inr, issue["state"]))

print("%d issues overall" % (issues))
print("%d PRs overall" % (prs))
# Now do the real counting excluding mass closure events
ONOBACK=0
CNOBACK=0
for category in CATS:
    ofnoback=0
    cfnoback=0
    for ds in OPENED[category].keys():
        if not ds in MCD:
            ofnoback+=OPENED[category][ds]
            ONOBACK+=OPENED[category][ds]
    for ds in CLOSED[category].keys():
        if not ds in MCD:
           cfnoback+=CLOSED[category][ds]
           CNOBACK+=CLOSED[category][ds]
    print("KPI components %s: " %(category))
    print("  %d opened" % (ofnoback))
    print("  %d closed" % (cfnoback))
    print("  KPI[%s]=%d" % (category, cfnoback-ofnoback))
print("Overall:")
print("  %d closed" % (CNOBACK))
print("  %d opened" % (ONOBACK))
print("KPI: %d" % (CNOBACK-ONOBACK))
