# URL Claim Verifier

Repository: https://github.com/zwang1111/genlayer-url-claim-verifier

An Intelligent Contract that records whether the text of one public HTTPS page supports one short factual claim. Validators fetch and judge independently. Consensus compares only `verdict`: `supported`, `unsupported`, or `unclear`. The leader's `reason` is stored and is not required to match.

This is not a truth oracle. It does not judge real-world truth, source authority, identity, freshness, or completeness.

Source file `contracts/url_claim_verifier.py` is 22556 bytes. SHA-256: `d85c3f30f1c3b8acd6a74c07b090d7ae79988087a9061afad223371fd0162f74`. The constructor takes no arguments. The deployed bytecode was not changed after the reads below.

## Network record

Studionet, chain ID 61999.

| Item | Value |
| --- | --- |
| Contract | `0x4987f65A84d791a9F301A1C913Db327367F3eB67` |
| Deploy transaction | `0xdeaa10b3c41b62870bd1a6e2a47fb55d76d65f7f1630cbf700ad2aca5a6f147b` |
| Deploy receipt | `FINALIZED`, `MAJORITY_AGREE`, leader `agree`, execution `SUCCESS` |

- Contract: https://explorer-studio.genlayer.com/address/0x4987f65A84d791a9F301A1C913Db327367F3eB67
- Deploy transaction: https://explorer-studio.genlayer.com/tx/0xdeaa10b3c41b62870bd1a6e2a47fb55d76d65f7f1630cbf700ad2aca5a6f147b

Studio import URL, confirm the page actually loads this address before relying on it:

https://studio.genlayer.com/?import-contract=0x4987f65A84d791a9F301A1C913Db327367F3eB67

Walkthrough video: https://youtu.be/pKF7O7sH5_k

That video is an evidence walkthrough of the deployment and the two writes. It is not a continuous screen recording of the whole session.

## Writes that finalized

No redeploy. `get_count` after both writes is `2`.

### Claim 1, `unclear`

| Field | Value |
| --- | --- |
| URL | `https://docs.genlayer.com/developers/networks` |
| Claim | `Studionet has chain ID 61999.` |
| Transaction | `0x00085757374867ef12a81273b94ec5a39939bb056e0165ea41c8c2e4af7985a9` |
| Receipt | `FINALIZED`, `MAJORITY_AGREE`, execution `SUCCESS` |
| `claim_id` | `1` |
| `verdict` | `unclear` |
| `excerpt` | empty |
| `reason` | The provided page does not mention Studionet or any chain ID, so it neither supports nor contradicts the claim. |

https://explorer-studio.genlayer.com/tx/0x00085757374867ef12a81273b94ec5a39939bb056e0165ea41c8c2e4af7985a9

This result is `unclear`. It is not `supported`.

### Claim 2, `supported`

| Field | Value |
| --- | --- |
| URL | `https://example.com/` |
| Claim | `This domain is for use in documentation examples without needing permission.` |
| Transaction | `0x410bc00f757991606ab309ebc8de6713b5da4b2630740882f63fdf1dcc06b304` |
| Receipt | `FINALIZED`, `MAJORITY_AGREE`, execution `SUCCESS` |
| Validator votes | `AGREE`, `AGREE`, `IDLE`, `AGREE`, `IDLE` |
| `claim_id` | `2` |
| `verdict` | `supported` |
| `excerpt` | `This domain is for use in documentation examples without needing permission.` |
| `reason` | The page text directly states the claim verbatim. |
| `leader_page_chars` | `171` |
| `leader_page_truncated` | `false` |
| `leader_caution_flags` | `[]` |
| `recorded_at` | `2026-11-09T05:25:15.680643Z` |
| `requester` | `0xDAab6b755FC2A11529042162492F6E8f50c181b4` |
| `get_latest_id` | `2` |

https://explorer-studio.genlayer.com/tx/0x410bc00f757991606ab309ebc8de6713b5da4b2630740882f63fdf1dcc06b304

The full `get_record("2")` object is in `evidence/readback.json`.

## Use

`verify_claim(url, claim)` fetches the page and stores one JSON record.

- `url`: public `https`, 12–500 characters, no credentials, no IP host, no local or internal suffix.
- `claim`: 8–280 characters after whitespace cleanup.

Reads: `get_record(claim_id)`, `get_latest_id(url)`, `get_count()`, `get_spec()`.

A decisive verdict must include a 16–180 character excerpt copied from the fetched page text. If the excerpt is missing, or if it overlaps one phrase in a fixed instruction-like list, the stored verdict is `unclear`. That list is not general prompt-injection protection. Consensus compares only `verdict`.

## Limits

- The check is only about the fetched page text.
- URL checks are syntactic. They do not prove the host is reachable or safe.
- JavaScript-only pages can look empty and then return `unclear`, because the contract uses HTTP GET plus tag stripping, not a browser render.
- If validators disagree, storage does not change.

## Runner

The first line pins `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`. The contract class is `gl.Contract`.

License: MIT.
