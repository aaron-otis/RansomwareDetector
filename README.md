# RansomwareDetector

Attempts to detect ransomware based on properties of of a binary.

## Dependencies
Relies on the binary analysis framework [angr](https://github.com/angr/angr). Follow the instructions on the official [website](http://angr.io/).


## How does it work?
This is still a work in progress, so this will be updated as more concrete versions are developed.

Attempts to detect cryptographic primitives using several different identifying properties. The following lists the properties that are planned to be implemented:

- [x] Per [Gröbert, et al.](https://link.springer.com/chapter/10.1007/978-3-642-23644-0_3), cryptographic binaries have many loops and makes excessive use bitwise arithmetic.
- [ ] Cryptographic API use.
- [ ] Writing to many files.
- [ ] Common ransom messages.
