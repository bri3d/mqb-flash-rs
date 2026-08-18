# mqb-flash-rs

This project aims to port https://github.com/bri3d/VW_Flash to Rust.

It is currently a work in progress:

* Simos18 re-flashing is tested
* Simos18 unlocking is somewhat tested
* Other control modules (Haldex, DSG) are UNTESTED.

It also introduces several new tools: 

* mqb-a2l-viewer : this is a diffing tool which will diff two binaries provided an A2L. its main differentiator, besides being very fast, is that it will show and analyze issues with shared axes. This is intended as a compliment to Tuner Pro.
* mqb-logger-gui : this is not yet a full-fledged logger, but rather an editor for SimosTools CSV files given an A2L. We had some small tools for this before (a2l2csv etc), but this is a real application with a nice UI. It's also, again, very fast.
* mqb-immo-gui: this is a GUI for performing Immobilizer operations

There are useful crates in here for SA2 (should be complete), FRF (it's simple so this should work on all of them), A2L (outrageously incomplete to the spec but should work for characteristics and measurements across most common ECUs), Simos18 NVRAM encryption, Immo 5, and ODX (VERY VERY incomplete, really only good for Simos18).

## AI Use

Yes, this project was mostly written by Claude, but with extremely heavy supervision. This was a fun AI-assist code project; Claude does a great job with Rust since it doesn't need to write 2+2=4 typo prevention tests and can focus on the actual code.

Things Claude did that were weird:

* Refused to implement LZSS and implemented LZO instead, repeatedly. I'm really not sure what was going on here; the Python version was very clear. I got it to snap out of it by making it write a test to 1:1 the Python and Rust compression outputs.
* Picked seemingly randomly numbers for IOCTLs in J2534, message counts for J2534 receive buffers, etc. - this is an LLM classic (being bad at numbers) but it was funny to observe. I just fixed most of these by hand, although for a few I asked Claude why the numbers didn't match up.
* Random stubborness and sycophancy in turns; mostly, Claude insisted that an issue caused by trying to read 8 messages into a J2534 buffer and then crashing when it timed out was actually a hardware issue, when it clearly was not.

Overall, I would recommend Claude + Rust - the language really helps avoid the massive cost/token/context/pain overhead of using Claude for languages which require extensive runtime sanity checking via tests that validate things like "the function is named what the function is named."

## Architecture Decisions

* Uses `I-CAN-Hack` `automotive` crate; this seems good and I like the author, so why not.
* Uses `iced` for GUI. I love the Elm-ish functional style. I loved Elm when it was popular so it's fun to go back to the same idea. My main beef with it is that there is no built in keyboard accelerator support of any kind, which is ridiculous from both an efficiency and accessibility standpoint. Overall, pretty nice though.
* The overarching goal was reusability and a mostly functional design; nothing should depend much on global state and each crate should be drop-in compatible in a new project, within reason.
