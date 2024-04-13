# PasswordStore Audit/Review - Lesson Notes

## Overview

The project we are auditng is a very small codebase because the focus of this lesson is to go over phase 1 of the security review process:

1. Scoping
2. Reconnaisance
3. Vulnerbaility Identification
4. Reporting

We will look at each stage of the forementioned steps and will build a report at the end of this lesson to show our findings.

## Scoping

### They only provided an Etherscan link?

Get the codebase and contracts and understand the scope on what we are going to audit.

For this lesson, we imagine a team reached out for an audit and simply sent through a sepolia etherscan address:
[PasswordStore - Sepolia Etherscan](https://sepolia.etherscan.io/address/0x2ecf6ad327776bf966893c96efb24c9747f6694b).

Examining the etherscan link, we can see that there is a single contract that is verified in Etherscan. They provide no further information or actual code files and this is very very bad! 

It is not uncommon for a project to simply just refer you to Etherscan to view the codebase. If a real world project is sending you just an Etherscan link, this should raise red flags - this is not professional and potentially they have not done enough due dilligence to get to the point of deploying and reasdy for an audit. We don't have enough confidence - There is zero documentation or history of tests, no indication that we can fully understand and trust the work thats been done! It does not pass the Rekt test.

Perhaps this is a deliberate, malicious move by the team that reached out to you because they are trying to by-pass listing requirements of a token. [Coinbase](https://www.coinbase.com/blog/a-guide-to-listing-assets-on-coinbase) has a number of things they evaluate when deciding to list something or not, one of the things they look at is: "The asset never received a security audit from a reputable auditing firm, especially if the code is complex or novel". Perhaps, this project is trying to quickly get something like this done so that they can get it listed somewhere to perform something malicious or scammy.

If this happens in real life, you would not work with this project until they can pass the basic Rekt test. Or, potentially you could propose that the engagement extends beyond just a security review and instead building of test suites, assiting in documentation, etc - so that you can make this codebase more mature.

### Access to Git repository in GitHub

In this lesson, we imagine that the clients ended up having a Git repository in GitHub for us to access - MUCH BETTER!

When we look at V2 version of the project we can see a basic foundry set up, some standard folders and no test folder. This still isn't great but its so much better. The problem still lies with what is actually in scope? What are we going to be conducting a security review on? What is all the information we need to carry out the review?

To help us get set up in the right direction, we can use the Cyfrin 'minimal-onboarding-questions.md' (Copy is stored in the lesson_support_files folder too) file to get us started and have the project answer.

There are other more extensive onboarding questionnaire's that we can use too, and these extend beyond just the minimal version and really help us establish everything. The 'extensive-onboarding-questions.md' file is stored in the lesson_support_files folder and is very similiar to what Cyfrin use when engaging with clients.

#### The project has filled out the questionnaire

I have included the filled questionnaire in the lesson-project-onboarding folder.

In the file, they specify a whole bunch of information,. inlcuding what git commit hash we are conducting our audit/review on, what roles there are in the project, about section detialing what the protocol is about, they also detial that there is only 1 file in scope of this audit - PasswordStore.sol.

#### Checking out a specific commit hash from a git repository

First, use 'git clone URL_OF_REPO' to create a clone of the repository - ENSURING YOU ARE ON THE CORRECT BRANCH.
```shell
 $ git clone https://github.com/Cyfrin/3-passwordstore-audit.git
```

After creating a copy of the repository, navigate to that repo folder in the terminal and run the command
```shell
$ git checkout HEXVALUEOFHASHEDCOMMIT

$ git checkout 7d55682ddc4301a7b13ae9413095feffd9924566
```

This will check out the specific commit hash with a temp status of not affecting anything in the repo because nothing will be saved. If we want to save any of the changes, we need to create a new branch and switch to that branch name
```shell
$ git switch -c <new-branch-name>
$ git switch -c passwordstore-audit

$ git branch
  main
* passwordstore-audit
```
Git branch can show us which branhc we are on, look for the asterix in the output from the command.

### Getting project stats

[cloc - cloc counts blank lines, comment lines, and physical lines of source code in many programming languages](https://github.com/AlDanial/cloc)
```shell
$ cloc ./src/PasswordStore.sol

$ cloc ./src/


$ cloc ./src/
       1 text file.
       1 unique file.
       0 files ignored.

github.com/AlDanial/cloc v 2.00  T=0.01 s (81.9 files/s, 3357.9 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
Solidity                         1              6             15             20
```

### Project keeps trying to include a bunch of unused dependencies when running 'forge build'?

Sometimes, a project may have default settings and dependencies set up that aren't required for the project. This should be noted too.

Now in terms of your local verison that you are working with, there are a couple of things to look at:

- Check what is detailed in the .gitmodules file and remove whatever isn't needed
- Check what is in the lib folder that has no impact on the project

## The "Tincho" Methodology

Tincho is one of teh most well known security researchers of Web3 in the entire world. The below is an overview of his methodology of conducting a secutrity review:

1. Download teh codebase
2. Read the documentation
3. Bring and use the tools you are best with
4. Use cloc or Solidity Metrics to help get stats on the different files of the codebase to help figure out what files are probably the most complex or least complex.
5. Use a method to track progress agsinst each file
6. Start with little legos and work up to the most complex files
7. Adopt an attacker mindset when reading through code of how can I break this - e.g. is this ERC20 token contract good for any other token out there? what about weird tokens? like USDT that doesnt return a boolean on transfers
8. Add notes in the code base - show where oyu have been, questions to explore or ask the dev team
9. Have a notes file to write thoughts and ideas into
10. Don't get stuck in rabbit holes of the single thing you are trying to audit - e.g. spending days learning about DNS and forgetting that you're their to review ENS and losing that vision and mindset
11. Use tests - fuzz testing, stateful fuzzing (invariant in Foundry) testing, use tools to test things youhave inclination that something is wrong
12. Maintain communication channels to developers. They will always have more context. You should rely on them but don't give too much trust as you are the hired expert for this review. Don't be afraid to ask questions.
13. Timebox yourself - theres always another line to check, another attack vector to look at. Timebox yourself so you can get good coverage in the limited time you have.
14. Remember there is no perfect auditor. People will miss things. Just put in best effort and try to minimise any issues that you could miss.
15. Write a very very good report for the team to look at and implement fixes
16. Conduct another review post-fixes
17. You should be valuable to a project regardless whether or not a critical finding was found. It is also not your sole responsibility if a bug was missed, you are part of a journey that the project undergoes and all have a role to play

## Recon

### Context

Read any docs to help get context of what the protocol is trying to do.

Feel free to generate diagrams to help build the context of what the protocol is trying to do.

We can use Solidity Metrics extension to help with this.

### Walkthrough the code

Take the time to start ot manually go over the codebase of contracts. Remembering to begin with the smaller lego blocks first before the castles of complexity.

## Vulnerability Identification

It is sometimes possible that the Recon phase and this phase overlap due to th every nature of reading through the code.

After completing recon and gaining even more context, create a notebook somewhere and begin to jot down some ideas. A great place to start is to challenge yourself to summarise what the protocl is trying to do in your own words, and what features is uses to achieve this, plus any stand out invaraints that you identify.

Also begin to write down some possible attack vectors that may be applicable to this codebase. Inluding why and how they are relevant to this project/protocol.

### Protocol's Test Suite

Remember that it your role to do whatever you can to make the protocol more secure.

This often means looking into and improving the protocols test suite and engineering practises.

Plus, tests can give you a hint into what the protocol is/isn't testing for. Which might tell you where bugs may be.

## Reporting Phase

Good reporting is so crucial to helping not just the protocl, but to also help yourself. Remembering that you are trying to make the protocol safer, if you can't convey your findings in a way that allows the protocol to improve and be more secure - you have failed.

Plus, when it comes to auditing contests your reporting is used to prove to judges why this is an issue that must be fixed. Again, to make the protocl safer.

Doing this well helps your personal brand too!

### Findings Layout

Remember that we have 3 things to achieve with regards to showing our findings as succient as possible:
1. Convince the protocol this is an issue
2. How bad this issue is
3. How to fix the issue

There are many ways to write up a finding, but for now we are going to focus on the minimal layout provided by Cyfrin. 
___
### [S-#] TITLE (Root Cause + Impact)

**Description:** 

**Impact:** 

**Proof of Concept:**

**Recommended Mitigation:** 

Where S is the severity, # is the order number of finding of that severity.

When referencing variables or functions in your findings, you can use \` (backticks) to make the variable stand out from the rest of the text. It is also standard practise to include the contract name where the variable or function exists by using 2 colons to separate the contract and the variable or function name.

For example:

The variable `DemoContract::myVariable` is intended to store ... However, anybody can call `DemoContract::setMyVariable` to change the value of the variable resulting in ...


___

### How to write findings well

1. Title
   1. give the root cause + impact
   2. succint and on point
   3. e.g. Variables stored in storage on-chain are visible to anyone, Storing of the password on-chain makes it visible to anyone, and no longer private.
2. Description
   1. Succint but detailed to prove the issue
   2. Provide enough detail so that the issue is understood by the protocol (or judge)
3. Impact
   1. You must succintly describe the impact of the issue to the protocols inteded usage or functionality
   2. Use words that align with the level of impact of the issue
4. Proof of Concept/Proof of Code
   1. This is our burden of truth to show how the issue can be exploited
   2. Early in your career, these POCs are extremely valuable to ensure that issues are listened to
5. Reccomendation
   1. Provide the information needed so that the protocol can rectify the issue
   2. Sometimes, the issue found can cause an entire re-think of the project if the issue breaks significant functionality or intended operation of the protocol. In situations like this, it is important to still provide a thoughtful and well explained reccommendation - sometimes even prompting them to explore other avencues that could help keep them aligned with their goals, but done in a more secure method.
   3. You can provide exact code to use to rectify the issue too

## Quick section on Reading any data from the blockchain

For this project, we are going to use Anvil and use the deploy script to deploy this contract to the local Anvil blockchain

1. Start anvil chain
2. Deploy using deploy script
3. use ```cast storage <address> <storage slot> --rpc-url <RPC URL>``` to read data. We can get the storage slot by looking at the order of variable declaration in the code base.
4. Will return the bytes, hex encoded value that is stored in that location
5. Use ```cast <COMMAND> <RETURNED_VALUE>``` to decode the value into the data type
   1. e.g. ```$ cast parse-bytes32-string  0x6d7950617373776f726400000000000000000000000000000000000000000014``` = ```myPassword```

## Determining the severity of an issue

[Cyfrin](https://docs.codehawks.com/hawks-auditors/how-to-evaluate-a-finding-severity) have a nice summarisation of determining the severity of an issue. Which includes the 3 criteria to be assessed:

1. Impact on the protocol: How severe would the potential damage be to the protocol if the vulnerability were exploited?

2. Likelihood of exploitation: How probable is it that an attacker would exploit this vulnerability?

3. Degree of judge/protocol subjectivity

**Note: CodeHawks uses 3 tiers of severity: High, Medium, Low - some other places include the critical severity too**

To determine the severity, we corss examine the impact of the attack and the likelihood of the attack - using a visual matrix.

## Generating final report

There are some useful templates that exist that we can leverage to write our final reports.

[Cyfrin](https://github.com/Cyfrin/audit-report-templating) provide a free template and guide on generating a PDF version of the report. They also provide alternative mthods to generating a PDF version of the report too.



