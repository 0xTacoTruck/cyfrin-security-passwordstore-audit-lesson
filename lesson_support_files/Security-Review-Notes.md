# Project overview in my own words

This is a single smart contract that should allow the contract deploy to store a password and retrieve it later using 2 functions - setPassword and getPassword. No other users should be able to set the password or get the password.

# Attack vector ideas

- Access control
  - Are the proper access controls in place for calling the 2 functions?
- Reentrancy
  - Is reentrancy an issue in function design?
- Input validation
  - Are the proper input validation in place for calling the 2 functions?
- Data visibility
  - Are variables being used knowing that their values could been seen on the blockchain? e.g. don't store crucial personal information or banking information in an unencrypted way.
- DoS
  - Is it possible that a malicious ttacker could cause a DoS attack? Could they prevent teh updating of password or retrieving it?
  

# Project test suite

- It is very very minimal and is only unit testing which favours bias of expected happy path
- Lacks tests trying to break logic
- No fuzz tests or invariant stateful fuzzing tests
- No tests for access control