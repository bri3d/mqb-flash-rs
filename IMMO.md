# VW IMMO 5

VW Immobilizer 5 / WFS 5 is a very simple system which allows modules to attest that they share the same secret key material (CS) and master key (MK). It protects against replay attacks and against unauthenticated attackers with CANbus access gaining the ability to start or drive a vehicle without knowledge of the secret key material.

In this repository, we provide an emulator for the Immobilizer 5 Master (Instrument Cluster) which can release sub-modules (ie - ECU) provided the module's shared key material. Note that this does NOT enable car theft or break the security boundary of the immobilizer in any way as the secret key material still must be extracted; it's just a convenient way to work on the bench without needing a full immobilizer participant system.

The secret key material is always read protected on all control modules where it is present. On Simos18, it lives in DFlash records, which are stored using an EEPROM emulation system and encrypted with a slightly warped variant of Hitag2, keyed using the Tricore MCUID. The Hitag2 variant is even more cryptographically weak than normal Hitag2, but it doesn't matter, because anyone in a position to read DFlash can also simply read the MCUID anyway and produce the key and IV.

We provide a tool to read, decrypt, and adapt (tamper/alter) DFlash given DFlash and an MCUID. This data can be obtained using the Simos18 SBOOT exploit.

We also provide the ability to download (adapt) new Immobilizer data to a control module once the key is known, due to a bizarre property of the immobilizer: the download functionality is fully symmetric and is protected only by the same secret key material. This is an excellent breakthrough for repairing vehicles using junkyard ECUs; once the CS is dumped from both the junkyard ECU and the target car, the car's ECU can be cloned onto the junkyard ECU without issue (note that at this time this requires opening both ECUs; there are other ways to acquire the CS which we will leave as an exercise to a competent reader to avoid theft issues).

## Immo Handshake

It's really this simple:

Cryptographic assertion material is produced by `CRC32(AES128(CS, block))`, where both CS and block are 128 bits (16 bytes).
 
Block is `MK [4] ‖ idxTun [1] ‖ operandA [4] ‖ operandB [4] ‖ domain [3]`

MK is a shared key unique to a vehicle type. CS is the secret key material for the immobilizer system. idxTun is the Tuning Index / Power Class, a unique byte which prevents ECU and TCU calibrations from being cross-flashed between vehicles. operandA and operandB are usually random numbers - which ones depends on the phase / variant of the handshake. "domain" is unique bytes which signify the handshake phase and direction (preventing replay in the opposite direction).

There are three basic variants which use the cryptographic assertion material in different ways, along with two two-byte "PINs", here called Km and Ks.

"PINs" are learned by each module after it is programmed with the CS material, providing an additional lock above the "remote" / programmed adaptation.

### Bi-directional, consisting of four messages

*Round 1* : the participant publishes its random and collects the master's:

```
Participant (0x10): [0x01, Rs0, Rs1, Rs2, Rs3, 0x00, 0x00, 0x00]
Master (0x11): [  - ,  - ,  - ,  - , Rm0, Rm1, Rm2, Rm3 ]
```

*Round 2* : both sides now have both randoms.

```
Cm = CRC32(AES(CS, MK ‖ idxTun ‖ RndSlave  ‖ RndMaster ‖ 0C 0D 0E))
Cs = CRC32(AES(CS, MK ‖ idxTun ‖ RndMaster ‖ RndSlave  ‖ 05 06 07))

Participant(0x10): [0x02, Cs0, Cs1, Cs2^Ks0, Cs3^Ks1, 0x00, 0x00, status]
Master(0x11): [ Cm0, Cm1, Cm2^Km0, Cm3^Km1, -, -, -, stMst ]
```
### Participant -> Master RNG Only

```
Cs = CRC32(AES(noKeySecu, MK ‖ idxTun ‖  RndSlave ‖ 01 02 03 04 05 06 07))
Cm = CRC32(AES(noKeySecu, MK ‖ idxTun ‖ ~RndSlave ‖ 08 09 0A 0B 0C 0D 0E))

Participant (0x10): [Rs0, Rs1, Rs2, Rs3, Cs0, Cs1, Cs2^Ks0, Cs3^Ks1]
Master (0x11): [Cm0, Cm1, Cm2^Km0, Cm3^Km1, -, -, -, stMst]
```

### Master RNG only:

```
Cm = CRC32(AES(noKeySecu, MK ‖ idxTun ‖ 63 61 73 63 ‖ RndMaster   ‖ 0F 10 11))
Cs = CRC32(AES(noKeySecu, MK ‖ idxTun ‖ RndMaster   ‖ 63 61 73 63 ‖ 11 12 13))

Participant (0x10): [0x03, Cs0, Cs1, Cs2^Ks0, Cs3^Ks1, 0x00, 0x00, status]
Master (0x11): [ Cm0, Cm1, Cm2^Km0, Cm3^Km1, Rm0, Rm1, Rm2, Rm3 ]
```

Adaptation is driven by the following UDS services, which are proxied directly to the immobilizer code by the "hosting" control module, and therefore aren't SecurityAccess or Session gated in most modules:

| `22` read | `0x2E0` | 1 | 4 B — get challenge |
| `22` read | `0x2ED` | 3 | 10 B — adaptation status |
| `22` read | `0x2EE` | 4 | 10 B — live immobilizer state |
| `22` read | `0x2EF` | 5 | 6 B — lockout timers |
| `22` read | `0x2F9` | 7 | 5 B — signed identity checksum |
| `22` read | `0x2FF` | 8 | 19 B — fault/environment snapshot |
| `22` read | `0xF190` | 9 | 17 B — VIN |
| `22` read | `0xF17C` | 11 | 23 B — FAZIT identification string |
| `2E` write | `0x2E1` | 2 | 4 B — **login** |
| `2E` write | `0x2E2` | 6 | 52 B — **download / adaptation** |


Login is used to flip certain flags (CCP/Memory inhibit, Power Class failure, etc.) without reprogramming the immobilizer completely. It works like this:

```
22 02 E0                     ->   62 02 E0 <c0 c1 c2 c3>
```

```
block  = subFunc | param | c0 c1 c2 c3 | 01 02 03 04 05 06 07 08 09 10
crc16  = CRC16-CCITT-FALSE( AES128-ECB-Encrypt(noKeySecu, block) )
pinHi  = crc16 >> 8 ,  pinLo = crc16 & 0xFF
```

```
2E 02 E1 <pinHi> <pinLo> <subFunc> <param>   ->   6E 02 E1
```

The main subfunctions and parameters useful to us are:

Subfunction 4 params 0x80: enter adaptation mode. This clears the PIN adaptation and unlocks the PClass error inhibition, which will allow the user to fix an "immo brick" due to PClass mismatch.

Subfunction 0x10 params 00 and 01: enable/disable CCP and read/writememory. On Simos18, these are still very locked down outside of Sample mode, but this opens attack surface and is just interesting in general. This could be helpful in reversing other control modules, too.

Download is comically simple:

`2E 02 E2 <48 bytes AES-ECB ciphertext> <4 bytes CRC32, big-endian of plaintext>`

| Offset | Field |
|---|---|
| `0x00..0x10` | 17-byte VIN |
| `0x11..0x20` | new CS, 16 bytes |
| `0x21` | `idxTun` (PClass) |
| `0x22` | flags: `0x80` -> `stStatFct = 4` (adapt), `0x40` `bAuthMute`, `0x20` `bVldChkDi`, `0x10` `bTrigFctDi`, `0x08` `bLimModEna` |
| `0x23` | Master Key selection/index |
| `0x24` | command, see below |
| `0x25..0x2F` | must be zero (not checked when command is 3) |

Command 3 is "write full data", Command 1 is "fully clear", Command 2 is "clear but take new key."

The `mqb-immo-gui` tool provides all of this functionality in a convenient UI.