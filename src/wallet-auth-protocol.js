// Copyright 2026 Douglas Borthwick / InsumerAPI
//
// Licensed under the Apache License, Version 2.0.

'use strict'

/**
 * Abstract base class defining a new WDK protocol category: Wallet Auth.
 *
 * OAuth proves who you are. Wallet auth proves what you hold.
 *
 * Alongside WDK's existing Swap, Bridge, Lending, and Fiat protocols, this
 * defines a pre-transaction verification protocol: given a wallet and a set
 * of on-chain conditions, return a cryptographically signed pass/fail
 * (attestation) or a multi-dimensional trust profile. The output is an
 * ECDSA-signed result the caller can verify offline; no secrets, no
 * identity-first, no static credentials.
 *
 * Implementations (e.g. InsumerWalletAuthProtocol) call an external
 * verification service and return signed results. The protocol itself never
 * touches private keys or broadcasts transactions — it runs before, not
 * during, the signing flow.
 *
 * Shape-compatible with upstream WDK protocol base classes and intended to
 * be proposed for inclusion in @tetherto/wdk-wallet/protocols.
 */

/** @typedef {import('@tetherto/wdk-wallet').IWalletAccountReadOnly} IWalletAccountReadOnly */
/** @typedef {import('@tetherto/wdk-wallet').IWalletAccount} IWalletAccount */

/**
 * @typedef {Object} Condition
 * @property {"token_balance"|"nft_ownership"|"eas_attestation"|"farcaster_id"|"evm_view_call"|"ratio_to_amount"|"ratio_to_supply"|"erc8004_agent"|"erc7710_delegation"|"account_code"} type
 * @property {string} [contractAddress]
 * @property {(number|string)} [chainId]
 * @property {(number|string|bigint)} [threshold] - Minimum balance in token units. Sent to the API as a decimal string; keys minted today require the string form.
 * @property {number} [decimals] - Optional. Leave it out: the token's own decimals are always read from the chain. If sent it is only a cross-check, and a value that differs from the token's own decimals is rejected with a 400.
 * @property {string} [schemaId]
 * @property {string} [attester]
 * @property {string} [indexer]
 * @property {string} [template]
 * @property {string} [currency] - XRPL trust line currency code (e.g. "RLUSD"). Required for XRPL trust line tokens. Case-sensitive: send it exactly as the issuer created it.
 * @property {(number|string)} [taxon] - XRPL NFToken taxon filter (optional): an integer from 0 to 4294967295, as a number or its digits.
 * @property {string} [assetCode] - Stellar trustline asset code (e.g. "USDC"): 1 to 12 letters and digits. Required for Stellar trustline tokens (contractAddress is the issuer's G-address); not used for native XLM.
 * @property {string} [selector] - evm_view_call: canonical signature of a single-address-argument view function returning bool, e.g. "hasAccess(address)". EVM chains only.
 * @property {string} [multiple] - ratio_to_amount: collateralization multiple as a decimal string.
 * @property {string} [amount] - ratio_to_amount: reference amount in token units as a decimal string.
 * @property {string} [minFraction] - ratio_to_supply: required share of totalSupply, decimal string in (0,1].
 * @property {string} [agentId] - erc8004_agent (Base only): the agent ID as a uint256 decimal string. Met iff the wallet owns the agent NFT or is the registry agentWallet binding; registration is permissionless, no vetting implied.
 * @property {string} [delegationManager] - erc7710_delegation (Base only): recognized MetaMask Delegation Framework manager address.
 * @property {string} [expectedDelegator] - erc7710_delegation: the principal the caller asserts. Required; the condition fails unless the delegation's delegator matches.
 * @property {Object} [delegation] - erc7710_delegation: the signed delegation ({delegator, delegate, authority, caveats, salt, signature}). Met iff the wallet is the delegate, the signature verifies (EOA or ERC-1271), unrevoked at the anchored block, all caveat enforcers recognized, time windows satisfied. Limits are reported as declaredLimits, not simulated; these attestations expire in 5 minutes.
 * @property {"none"|"eip7702"|"contract"} [expect] - account_code (EVM chainId only, no contractAddress): the code state the wallet address itself must be in at the anchored block. Required for account_code. "none" = no code (a plain key account); "eip7702" = the EIP-7702 delegation designator (a key that has delegated execution to a contract); "contract" = any other code (a smart-contract wallet, a protocol, a token). Exclusive on a chain. The result is the boolean met; the code and the delegation target are never returned.
 * @property {string} [delegate] - account_code with expect "eip7702" only (a 400 with any other expect): an EVM address; met iff the designator points at it. Echoed, lowercase, inside the signed evaluatedCondition.
 * @property {string} [label]
 */

/**
 * @typedef {Object} AttestOptions
 * @property {Condition[]} conditions - One to ten on-chain conditions to evaluate.
 * @property {string} [address] - Address to evaluate. Defaults to the attached account.
 * @property {string} [solanaAddress] - Solana address, if different from the default EVM address.
 * @property {string} [xrplAddress] - XRPL r-address.
 * @property {string} [bitcoinAddress] - Bitcoin address.
 * @property {string} [tronAddress] - Tron address (T-prefix, base58, 34 chars). Required for any `chainId: "tron"` condition.
 * @property {string} [stellarAddress] - Stellar address (G-prefix StrKey, 56 chars). Required for any `chainId: "stellar"` condition.
 * @property {string} [suiAddress] - Sui address (0x + 64 hex chars). Required for any `chainId: "sui"` condition.
 * @property {boolean} [jwt] - If true, request an ES256 JWT alongside the attestation.
 * @property {boolean} [merkleProof] - If true, request EIP-1186 Merkle storage proofs (costs 2 credits instead of 1).
 */

/**
 * @typedef {Object} AttestResult
 * @property {boolean} passed - True if every condition is met.
 * @property {Object} attestation - Raw attestation object (condition-by-condition results, block numbers, condition hash).
 * @property {string} sig - ECDSA P-256 signature over the attestation (base64).
 * @property {string} kid - Key ID identifying the signing key in the JWKS; it also selects the signed preimage (insumer-attest-v1 or insumer-attest-v2).
 * @property {string} [jwt] - ES256 JWT form of the attestation, when requested.
 * @property {string} [pqSig] - Post-quantum signature (ML-DSA-65, FIPS 204) over the same preimage under a post-quantum domain tag. Additive beside sig.
 * @property {string} [pqKid] - Key ID of the post-quantum key in the JWKS (insumer-attest-pq1, an RFC 9964 AKP entry).
 * @property {string} [pqJwt] - Post-quantum form of jwt (compact JWS, alg ML-DSA-65), when jwt was requested.
 * @property {number} creditsRemaining - Credits remaining on the API key after this call.
 * @property {number} creditsCharged - Credits consumed by this call.
 */

/**
 * @typedef {Object} TrustOptions
 * @property {string} [address] - EVM address to profile. Defaults to the attached account.
 * @property {string} [solanaAddress] - Optional Solana address (adds the 14-check solana dimension and lets the Solana rows inside institutional_stablecoins evaluate).
 * @property {string} [xrplAddress] - Optional XRPL r-address (adds the xrpl dimension: RLUSD, USDC, OUSG; and lets the XRPL row inside institutional_stablecoins evaluate).
 * @property {string} [bitcoinAddress] - Optional Bitcoin address (adds the bitcoin dimension: one native BTC presence check).
 * @property {string} [tronAddress] - Optional Tron address (adds the tron dimension: USDT, USD1, WBTC).
 * @property {string} [stellarAddress] - Optional Stellar address. Adds no dimension; lets the USDC and BENJI on Stellar rows inside institutional_stablecoins evaluate.
 * @property {string} [suiAddress] - Optional Sui address. Adds no dimension; lets the USDC on Sui row (institutional_stablecoins) and USDY on Sui row (tokenized_treasuries) evaluate.
 * @property {boolean} [merkleProof] - If true, request Merkle proofs (costs 6 credits instead of 3).
 */

/**
 * @typedef {Object} TrustResult
 * @property {Object} trust - Full trust profile (dimensions, checks, summary, profile id).
 * @property {string} sig - ECDSA P-256 signature over the trust object.
 * @property {string} kid - Key ID identifying the signing key in the JWKS.
 * @property {string} [pqSig] - Post-quantum signature (ML-DSA-65) over the trust preimage under a post-quantum domain tag.
 * @property {string} [pqKid] - Key ID of the post-quantum key in the JWKS (insumer-trust-pq1).
 * @property {number} creditsRemaining
 * @property {number} creditsCharged
 */

/** @interface */
export class IWalletAuthProtocol {
  /**
   * Evaluate one or more on-chain conditions against a wallet and return a
   * cryptographically signed pass/fail attestation. Runs server-side against
   * live chain state and never exposes raw balances unless merkleProof is
   * requested.
   *
   * @param {AttestOptions} options
   * @returns {Promise<AttestResult>}
   */
  async attest (options) {
    throw new Error('attest(options) not implemented')
  }

  /**
   * Return a multi-dimensional trust profile for a wallet: 155 base checks across
   * 27 chains in 10 dimensions (stablecoins, governance, nfts, staking,
   * institutional_stablecoins, tokenized_treasuries, stablecoin_deposits,
   * wrapped_bitcoin, names, account), up to 176 across 29 chains in 14 with the
   * optional Solana, XRPL, Bitcoin and Tron addresses, which each add their own
   * dimension. Stellar and Sui addresses add no dimension; their rows sit inside
   * the base dimensions and carry evaluated: false until the address is supplied.
   * Every check is a presence check; the account dimension reports whether
   * contract code or an EIP-7702 delegation is present at the address on
   * Ethereum, Base, Arbitrum, Optimism and Polygon. Dimensions come back in a
   * fixed order: the base ten, then solana, xrpl, bitcoin, tron when switched on.
   * trust.conditionSetVersion names the check list run (currently "2026-10-08").
   * The profile is signed as a whole.
   *
   * @param {TrustOptions} [options]
   * @returns {Promise<TrustResult>}
   */
  async trust (options) {
    throw new Error('trust(options) not implemented')
  }
}

/**
 * @abstract
 * @implements {IWalletAuthProtocol}
 */
export default class WalletAuthProtocol {
  /**
   * @param {IWalletAccountReadOnly | IWalletAccount} [account] - Optional wallet
   *   account to bind. When present, its address is used as the default subject
   *   for attest() and trust() calls.
   */
  constructor (account) {
    /**
     * @protected
     * @type {IWalletAccountReadOnly | IWalletAccount | undefined}
     */
    this._account = account
  }

  /**
   * @abstract
   * @param {AttestOptions} options
   * @returns {Promise<AttestResult>}
   */
  async attest (options) {
    throw new Error('attest(options) not implemented')
  }

  /**
   * @abstract
   * @param {TrustOptions} [options]
   * @returns {Promise<TrustResult>}
   */
  async trust (options) {
    throw new Error('trust(options) not implemented')
  }
}
