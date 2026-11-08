# payment-attack-surface

A **model**, not a list. Describe a payment system by 16 traits, get back the
concrete risks that follow, how to verify each one, and which PoC to run.

```bash
python3 pay_assess.py --preset gambling
```

## Why a model instead of a checklist

A list of "platforms to test" expires in a quarter. Payment architecture does
not. The 29 rules here fire on **structural traits** — multi-level splits,
fallback refunds, DCC pricing, pre-auth windows — so the output stays valid as
long as the architecture does.

## Profiles

16 fields: business type, payment method, settlement model, currency, risk
engine, reconciliation, refund routing, split depth, pre-auth, subscription,
affiliate program, payout mode, KYC level, 3DS mode, tokenization, device
fingerprint.

Five presets ship with it: `ecommerce`, `gambling`, `wallet`, `remittance`,
`indie`.

## Measured output

| Preset | Findings | Highest-priority hit |
|---|---|---|
| `gambling` | 13 | F1 multi-level fund penetration, F2 unlicensed clearing |
| `indie` | 13 | F3 settlement timing gap, B3 virtual-goods refund |
| `ecommerce` | 11 | F3, C2 currency mismatch |
| `wallet` | 9 | F4 payout automation abuse, F5 refund to non-original account |
| `remittance` | 9 | C1 DCC markup, B4 FX lock as a free option |

## Rule families

```
F  fund ownership    F1-F5  split penetration / unlicensed clearing /
                            settlement gap / payout / refund routing
C  pricing           C1-C4  DCC markup / currency mismatch / subscription /
                            pre-auth release
A  auth & risk       A1-A4  3DS / downgrade / rule enumeration / KYC
B  business logic    B1-B5  gambling deposit-withdraw / bonus wagering /
                            virtual goods / remittance / wallet balance
M  marketing         M1-M2  coupon & points arbitrage / tiered distribution
T  implementation    T1-T6  PIN block / magstripe downgrade / NFC relay /
                            tokenization / split injection / rounding
O  operations        O1-O5  reconciliation / back-office privilege /
                            device fingerprint / on-chain / gift-card codes
```

## Custom profile

```json
{
  "biz": "marketplace", "pay_method": "mixed", "settle": "split",
  "currency": "multi", "risk": "rules", "recon": "t1",
  "refund": "wallet", "split": "multi_level", "preauth": "none",
  "subscribe": "auto", "affiliate": "multi_tier", "payout": "auto",
  "kyc": "basic", "tds": "optional", "token": "custom", "device": "none"
}
```

```bash
python3 pay_assess.py --profile my.json --json
```

## Scope

Assessment framework. Every referenced PoC targets a local range, not a
production system.

MIT.
