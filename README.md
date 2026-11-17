# Nessa - Program Wide Homomorphism
To be exact, and precise; these are the obfuscation issues Nessa fixes:

* Secures code in isolation, you can't attack code in isolation; you must attack the entire call chain to deobfuscate a function.
* Allows for fast code to execute quickly with the security of its above head call chain, allowing no sacrifices for fast code; maintaining absolute security downstream by securing itself upstream.
* Forces the entire application to be attacked, flooding context windows as much as possible.

Nessa uses the following techniques in parallel as part of its obfuscation chain:
* [TLS Laundering](https://github.com/IntelSDM/TLSLaunderingPass)
* [Return Address Encryption](https://github.com/IntelSDM/RetCryptPass)
* [Caller Constant Key](https://github.com/IntelSDM/CallerConstKeyChain)
* [Condition Stomping](https://github.com/IntelSDM/ConditionStompingObfuscation)
<br>
If you have any bugs or want to do a better implementation, you can use these independent passes to test. <br>

## How Nessa Works
1) Scan for all none CRT/ None library functions. This gives us a list of all the organic program code.
2) Condition stomps, this takes all conditions, force inlines all their reliant code into the block. Stores and saves the runtime key. (This forces runtime dependency).
3) Takes the organic program functions, splits them from their call graph. Cloning them, so they have no xrefs.
4) We then build the keys for all the cloned functions, using the TLS laundering, Return Address Encryption, Caller Constant Key Chain.
5) We then encrypt the contents of all the functions using the keys. Encrypting: Strings, Jumps, Constants, Calls
6) We then clean up, to prevent any attacks easily resolving call chains, we then encrypt calls, constants with a basic xor, to kill off remaining xrefs on none obfuscated functions.

## How Nessaa protects you

* In step 3 we detached every organic function from the call chain. This means every function has a unique key, compromising one of the cloned functions doesn't compromise the rest.
* This means that every function is technically unique, FULLY reliant on information passed through from its caller. The TLS laundering and retcrypt, require you to know the call site to decrypt the contents.
* The callsite for ALL functions is unknown, including ones Nessa doesn't cover, so you can't brute force them easily by only taking functions with no xrefs and brute forcing an output.
* This means you MUST walk the entire program's execution from entrypoint.
* The caller const key chain is one of the most important parts, it launders the key up to 8 functions head of it, meaning it needs 8 functions of morphing to be resolved. This means basic unobfuscated functions can be in the chain without exposing the key.
* All of the encryption is an xor to a garbled key that is built up of all the environment based keys (the 4 passes). This means you are only doing a basic xor, very little overhead for fast executing code.
In the most basic of terms, you MUST attack the entire application linearly, its entire execution, as soon as you hit a stomped condition, you are forced to runtime analysis of all code past it; As soon as you hit unresolvable opaques or any form of heavy runtime reliant obfuscation, you can't reverse ANY FURTHER! <br>
This means if your entrypoint and everything else is unknown, such as using [self decaying code](https://github.com/IntelSDM/SelfDecayingCode), [Serverside code](https://github.com/IntelSDM/ServerSideCodeExecution), or anything too heavily reliant on runtime information. You are FORCED into runtime analysis for the whole binary! <br>

## What Nessa doesn't support

* Callbacks/hooks
* Functions with no call trace
* Polymorphic/ C++ class functions

## Graphs
Due to how Nessa works, it is impossible to properly demonstrate it in a tool like IDA. So MS paint will have to do.<br>
So this is what your normal call graph looks like: <br>
<img width="1455" height="610" alt="image" src="https://github.com/user-attachments/assets/dffd1719-7d0a-4a3c-b6bd-02f314f08822" />
Now Nessa takes this and clones the multi xrefs:<br>
<img width="1455" height="679" alt="image" src="https://github.com/user-attachments/assets/421f4468-8f3a-4384-b6ff-accb2ebc8273" />
Then it creates reliance upwwards(Shown with red "arrows"):
<img width="1455" height="679" alt="image" src="https://github.com/user-attachments/assets/4bc66923-894f-4c12-add4-a547cd73ab61" />
Then it encrypts all the data in the functions. This removes the calls, jumps, strings and constant data without the full reliance path being built. This removes the xrefs.<br>
<img width="1455" height="679" alt="image" src="https://github.com/user-attachments/assets/dfa02995-981c-4c46-b147-24bd3f2b7211" /><br>
Now if you wanted to attack function 10 , you need to know the keys from  Entrypoint, function 2, Function 6. Thats just to attack 1 of the function 10s.<br>


