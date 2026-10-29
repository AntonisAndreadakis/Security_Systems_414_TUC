# Remaining validation requiring a user decision

No approval has been received for the operations below. A goal-continuation
message is not approval. Ordinary non-root, offline tests remain permitted.

## Assignment 5: generated-fixture lab

Proposed test: inside the existing UID-10001, network-disabled Docker sandbox,
use a new `/work/lab-validation` directory to create three program-generated
text fixtures. Encrypt them, validate their recoverability, remove only those
generated originals, recover them, and compare their exact contents. Also check
tampered input rejection and preservation of an existing output.

The implementation uses `--lab` / `--recover` with `--approve-lab`. These flags
have not been invoked. The read-only source mount would protect host files;
the temporary container filesystem would hold all generated data and keys.
The ordinary simulation and recovery metadata checks have passed, but do not
establish the result of this proposed test.

The earlier user restriction against suspicious actions is why this specific
encryption/deletion/recovery test needs approval.

## Assignments 6 and 7

Live capture and real kernel firewall operations are untested. Existing policy
prohibits root attempts, and normal containers have no network capabilities.
These tests cannot be inferred as approved from opening Docker or requesting
Python ports. Offline packet fixtures and mocked commands remain the verified
coverage. A new environment/scope decision is needed before kernel integration.

## Assignment 8

The Python bytearray model and artifact inspection are tested. Native shellcode
execution and the original C exploit demonstration remain separate requirements;
they are not fulfilled by the model. No such execution has been approved or
attempted in this work.
