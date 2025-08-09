# Goal of this program is to review all open PROJECT issues and suggest possible/recommended next steps

PROJECT="openssl/openssl"

import requests
import os
from datetime import datetime, date, time, timezone

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

def feedback(message, id, dtd, holding, pr):
    print("%s: <a href='https://github.com/%s/issues/%d'>%d</a>" % ("PR" if pr else "Issue", PROJECT, id, id))
    print("-> Open since "+str(dtd))
    if (len(holding) == 0):
       print(message)
    else:
       print("%s (%s)" % (holding, message))
    print("<p>")

now = datetime.now(timezone.utc)

# iterate through all open issues -- these include PRs

# collect stats about issue, comments, labels associated with issue
# Goal is to make judgement calls at the end of each issue review iteration
# - whether an issue is triaged or actually inactive deserving closure for good
# - whether a PR deserves another review


# maximum number for API: 100; less is possible but less efficient (counting towards rate limit)
next = 'https://api.github.com/repos/'+PROJECT+'/issues?per_page=100'
issues = 0
while (next != ""):
  r = requests.get(next, headers=headers)
  rh = r.headers
  if "X-RateLimit-Remaining" in rh.keys():
     if int(rh["X-RateLimit-Remaining"]) < 100:
         print("Warning: Rate limit remaining: " + rh["X-RateLimit-Remaining"])
  next = getnextlink(rh)
  for issue in r.json():
     issues+=1
     inr = issue["number"]
     ispr = "pull_request" in issue.keys()
     author = issue["user"]["login"]
     dt = datetime.strptime(issue["created_at"], "%Y-%m-%dT%H:%M:%SZ")

     dtd = now-dt.replace(tzinfo=timezone.utc)
     if ispr:
         # now check review comments for this PR:
         nextreview = "https://api.github.com/repos/"+PROJECT+"/pulls/"+str(inr)+"/reviews"
         approvals = 0
         rcomments = 0
         changerequestedby = []
         while (nextreview != ""):
             rc = requests.get(nextreview, headers=headers)
             nextreview=getnextlink(rc.headers)
             lastreviewauthor = ""
             for rcomment in rc.json():
               rcomments = rcomments+1
               #print(rcomment.keys())
               lastreviewauthor = rcomment["user"]["login"]
               if (rcomment["state"] == "CHANGES_REQUESTED"):
                  changerequestedby.append(lastreviewauthor)
               if (rcomment["state"] == "DISMISSED"):
                  approvals -= 1
               if (rcomment["state"] == "APPROVED"):
                  adt = datetime.strptime(rcomment["submitted_at"], "%Y-%m-%dT%H:%M:%SZ")
                  # remove approving author from changerequestedby list
                  try:
                      while (len(changerequestedby)>0):
                          changerequestedby.remove(lastreviewauthor)
                  except ValueError:
                      print()
                  approvals += 1
               lastreviewdt = datetime.strptime(rcomment["submitted_at"], "%Y-%m-%dT%H:%M:%SZ")
     # also check labels (https://docs.github.com/en/rest/issues/labels?apiVersion=2022-11-28#list-labels-for-an-issue)
     # for presence of inactive label (and whether it's there longer than the last comment)
     # for presence of hold and/or triaged labels
     reqlabels = "https://api.github.com/repos/"+PROJECT+"/issues/"+str(inr)+"/labels"
     lresp = requests.get(reqlabels, headers=headers)
     # don't assume pagination to be an issue (TBC)
     inactive = 0
     holding = ""
     triaged = ""
     for label in lresp.json():
         if (label["name"] == "inactive"):
            inactive = 1
         if (label["name"].find("triaged:") == 0):
            triaged = label["name"]
         if (label["name"].find("hold:") == 0):
            holding = label["name"]

     if inactive == 0:
         if (triaged == "") and not ispr:
             feedback("Not triaged: Why?", inr, dtd, holding, ispr)
             continue  # to next issue
     else:
        feedback("Inactive: Delete?", inr, dtd, holding, ispr)

     ## now check issue comments:
     nextcomment = "https://api.github.com/repos/"+PROJECT+"/issues/"+str(inr)+"/comments"
     icomments = 0
     while (nextcomment != ""):
          cc = requests.get(nextcomment, headers=headers)
          nextcomment = getnextlink(cc.headers)
          lastcommentauthor=""
          for icomment in cc.json():
            icomments = icomments+1
            lastcommentbody = icomment["body"]
            lastcommentdt = datetime.strptime(icomment["updated_at"], "%Y-%m-%dT%H:%M:%SZ")
            lastcommentauthor = icomment["user"]["login"]
     if (lastcommentauthor == "nhorman" or lastcommentauthor == "t8m"):
         if (lastcommentbody.find("ping") >= 0 or (lastcommentbody.find("closed")>=0 and lastcommentbody.find("inactive"))):
             feedback("To be deleted", inr, dtd, holding, ispr)
             # activate these lines to actually close all issues slated for closure:
             #closeresponse = requests.patch("https://api.github.com/repos/"+PROJECT+"/issues/"+str(inr), headers=headers, json={"state":"closed"})
             #if (closeresponse.status_code != 200):
             #   print("deletion failed with response code %d" % (closeresponse.status_code))
             continue
     if ispr:
        if (rcomments > 0 and (lastcommentauthor == author or lastreviewauthor == author)):
          feedback("Last comment by author: Action: Re-Review due?", inr, dtd, holding, ispr)
        if (approvals == 1):
          feedback("--> 1 approval given: 2nd check due", inr, dtd, holding, ispr)
        if (approvals > 1 and len(changerequestedby)==0):
          feedback("--> Sufficient approvals given: Why still open?", inr, dtd, holding, ispr)
        if (rcomments == 0):
          feedback("-->Never reviewed: Why?", inr, dtd, holding, ispr)
        # TBD: Possible ToDos: 
        # check whether core team has left a comment (last?)
        # check for more labels' presence (knowing what they mean)
        # Link with Project association
        # Treat assigned issues differently (flag issues where assignee is not last comment author)
        # .....

# KPIs could be computed from the parameters collected, e.g.
# time passed since 1st approval could get a high score as could time passed without any triage, etc.


print("%d issues overall" % (issues))
