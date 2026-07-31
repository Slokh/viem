import type { Address } from 'abitype'
import { Hex } from 'ox'
import { EarnShares, TokenId } from 'ox/tempo'
import type { Account } from '../../accounts/types.js'
import { parseAccount } from '../../accounts/utils/parseAccount.js'
import { estimateContractGas } from '../../actions/public/estimateContractGas.js'
import { getBlockNumber } from '../../actions/public/getBlockNumber.js'
import { type GetLogsErrorType, getLogs } from '../../actions/public/getLogs.js'
import { multicall } from '../../actions/public/multicall.js'
import {
  type ReadContractReturnType,
  readContract,
} from '../../actions/public/readContract.js'
import {
  type SimulateContractReturnType,
  simulateContract,
} from '../../actions/public/simulateContract.js'
import * as internal_Token from '../../actions/token/internal.js'
import {
  type SendTransactionReturnType,
  sendTransaction,
} from '../../actions/wallet/sendTransaction.js'
import { sendTransactionSync } from '../../actions/wallet/sendTransactionSync.js'
import { writeContractSync } from '../../actions/wallet/writeContractSync.js'
import type { Client } from '../../clients/createClient.js'
import type { Transport } from '../../clients/transports/createTransport.js'
import { AccountNotFoundError } from '../../errors/account.js'
import type { BaseErrorType } from '../../errors/base.js'
import type { Chain } from '../../types/chain.js'
import type { Log } from '../../types/log.js'
import type { Compute, OneOf } from '../../types/utils.js'
import { encodeAbiParameters } from '../../utils/abi/encodeAbiParameters.js'
import { getAbiItem } from '../../utils/abi/getAbiItem.js'
import { parseEventLogs } from '../../utils/abi/parseEventLogs.js'
import { getAddress } from '../../utils/address/getAddress.js'
import { isAddressEqual } from '../../utils/address/isAddressEqual.js'
import { type ObserveErrorType, observe } from '../../utils/observe.js'
import { type PollErrorType, poll } from '../../utils/poll.js'
import { withResolvers } from '../../utils/promise/withResolvers.js'
import { stringify } from '../../utils/stringify.js'
import * as Abis from '../Abis.js'
import * as Addresses from '../Addresses.js'
import {
  GetVaultEngineChangedError,
  type GetVaultEngineChangedErrorType,
  WaitForPrivateDepositTimeoutError,
  type WaitForPrivateDepositTimeoutErrorType,
  WaitForPrivateRedeemTimeoutError,
  type WaitForPrivateRedeemTimeoutErrorType,
} from '../errors.js'
import type {
  GetAccountParameter,
  ReadParameters,
  WriteParameters,
  WriteSyncParameters,
} from '../internal/types.js'
import {
  type CallParameters,
  defineCall,
  pickWriteParameters,
  resolveCallParameters,
  resolveTokenWithDecimals,
} from '../internal/utils.js'
import type { TransactionReceipt } from '../Transaction.js'
import { getPortalAddress } from '../zones/zone.js'
import * as policyActions from './policy.js'
import * as tokenActions from './token.js'
import * as zoneActions from './zone.js'

/** TIP-403 policy ID that allows every sender, recipient, and mint recipient. */
export const alwaysAllowPolicyId = 1n

/** Admission-only TIP-403 policy attached to an Earn share token. */
export type ExitSafePolicy = {
  /** Compound policy attached to the Earn share token. */
  transferPolicyId: bigint
  /** Sender policy. Must be {@link alwaysAllowPolicyId} so holders can exit. */
  senderPolicyId: bigint
  /** Recipient eligibility policy. */
  recipientPolicyId: bigint
  /** Mint-recipient eligibility policy. Must match `recipientPolicyId`. */
  mintRecipientPolicyId: bigint
}

/** Receipts produced while configuring an exit-safe Earn policy. */
export type ExitSafePolicyReceipts = {
  /** Whitelist policy creation receipt. */
  eligibilityPolicy: TransactionReceipt
  /** Compound policy creation receipt. */
  compoundPolicy: TransactionReceipt
  /** Earn share token policy update receipt. */
  tokenPolicy: TransactionReceipt
  /** Eligibility policy admin transfer receipt, when an administrator is provided. */
  policyAdmin?: TransactionReceipt | undefined
}

/**
 * Creates and attaches an admission-only TIP-403 policy to an Earn share
 * token. Existing holders remain able to send shares while recipients and mint
 * recipients must belong to the same whitelist.
 *
 * The action submits three or four sequential transactions and is not atomic.
 * Use {@link validateExitSafePolicy} to verify the final state.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const account = privateKeyToAccount('0x...')
 * const client = createClient({
 *   account,
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const { policy, receipts } =
 *   await Actions.earn.configureExitSafePolicy(client, {
 *     accessAdministrator: '0x...',
 *     initialMembers: ['0x...', '0x...'],
 *     shareToken: '0x...',
 *   })
 * ```
 *
 * @param client - Client authorized to change the Earn share token policy.
 * @param parameters - Share token, administrator, and initial members.
 * @returns The configured policy IDs and transaction receipts.
 */
export async function configureExitSafePolicy<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: configureExitSafePolicy.Parameters<account>,
): Promise<configureExitSafePolicy.ReturnValue> {
  const account_ = parameters.account ?? client.account
  if (!account_) throw new AccountNotFoundError()
  const account = parseAccount(account_)
  const initialMembers = [
    ...new Set(parameters.initialMembers.map((member) => getAddress(member))),
  ]
  if (initialMembers.length === 0)
    throw new Error('At least one initial policy member is required.')

  const eligibility = await policyActions.createSync(client, {
    account,
    addresses: initialMembers,
    chain: client.chain,
    type: 'whitelist',
  } as never)
  const compoundPolicy = await writeContractSync(client, {
    account,
    abi: Abis.tip403Registry,
    address: Addresses.tip403Registry,
    args: [alwaysAllowPolicyId, eligibility.policyId, eligibility.policyId],
    chain: client.chain,
    functionName: 'createCompoundPolicy',
    throwOnReceiptRevert: true,
  } as never)
  const [compoundEvent] = parseEventLogs({
    abi: Abis.tip403Registry,
    eventName: 'CompoundPolicyCreated',
    logs: compoundPolicy.logs,
    strict: true,
  })
  if (!compoundEvent)
    throw new Error('`CompoundPolicyCreated` event not found.')

  const tokenPolicy = await tokenActions.changeTransferPolicySync(client, {
    account,
    chain: client.chain,
    policyId: compoundEvent.args.policyId,
    token: parameters.shareToken,
  } as never)
  const policyAdmin = isAddressEqual(
    parameters.accessAdministrator,
    account.address,
  )
    ? undefined
    : await policyActions.setAdminSync(client, {
        account,
        admin: parameters.accessAdministrator,
        chain: client.chain,
        policyId: eligibility.policyId,
      } as never)

  return {
    policy: {
      transferPolicyId: compoundEvent.args.policyId,
      senderPolicyId: alwaysAllowPolicyId,
      recipientPolicyId: eligibility.policyId,
      mintRecipientPolicyId: eligibility.policyId,
    },
    receipts: {
      eligibilityPolicy: eligibility.receipt,
      compoundPolicy,
      tokenPolicy: tokenPolicy.receipt,
      policyAdmin: policyAdmin?.receipt,
    },
  }
}

export namespace configureExitSafePolicy {
  export type Args = {
    /** Address that will administer recipient eligibility. */
    accessAdministrator: Address
    /** Addresses initially eligible to receive or be minted Earn shares. */
    initialMembers: readonly Address[]
    /** Earn share token. */
    shareToken: Address
  }
  export type Parameters<
    account extends Account | undefined = Account | undefined,
  > = GetAccountParameter<account> & Args
  export type ReturnValue = Compute<{
    /** Configured onchain policy IDs. */
    policy: ExitSafePolicy
    /** Receipts for each configuration transaction. */
    receipts: ExitSafePolicyReceipts
  }>
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Verifies that an Earn share token uses the expected exit-safe TIP-403
 * policy and that every required member can receive transfers and mints.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * await Actions.earn.validateExitSafePolicy(client, {
 *   accessAdministrator: '0x...',
 *   policy: {
 *     transferPolicyId: 3n,
 *     senderPolicyId: 1n,
 *     recipientPolicyId: 2n,
 *     mintRecipientPolicyId: 2n,
 *   },
 *   requiredMembers: ['0x...', '0x...'],
 *   shareToken: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Expected policy, administrator, and required members.
 * @returns Nothing when the policy is valid.
 */
export async function validateExitSafePolicy<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: validateExitSafePolicy.Parameters,
): Promise<validateExitSafePolicy.ReturnValue> {
  const { accessAdministrator, policy, requiredMembers, shareToken, ...rest } =
    parameters
  const [tokenPolicyId, compound, simplePolicy, memberResults] =
    await Promise.all([
      readContract(client, {
        ...rest,
        abi: Abis.tip20,
        address: shareToken,
        functionName: 'transferPolicyId',
      }),
      readContract(client, {
        ...rest,
        abi: Abis.tip403Registry,
        address: Addresses.tip403Registry,
        args: [policy.transferPolicyId],
        functionName: 'compoundPolicyData',
      }),
      readContract(client, {
        ...rest,
        abi: Abis.tip403Registry,
        address: Addresses.tip403Registry,
        args: [policy.recipientPolicyId],
        functionName: 'policyData',
      }),
      Promise.all(
        requiredMembers.map(async (member) => {
          const [recipient, mintRecipient] = await Promise.all([
            readContract(client, {
              ...rest,
              abi: Abis.tip403Registry,
              address: Addresses.tip403Registry,
              args: [policy.transferPolicyId, member],
              functionName: 'isAuthorizedRecipient',
            }),
            readContract(client, {
              ...rest,
              abi: Abis.tip403Registry,
              address: Addresses.tip403Registry,
              args: [policy.transferPolicyId, member],
              functionName: 'isAuthorizedMintRecipient',
            }),
          ])
          return { member, mintRecipient, recipient }
        }),
      ),
    ])

  if (tokenPolicyId !== policy.transferPolicyId)
    throw new Error('Earn share token transfer policy mismatch.')
  if (
    compound[0] !== policy.senderPolicyId ||
    compound[1] !== policy.recipientPolicyId ||
    compound[2] !== policy.mintRecipientPolicyId
  )
    throw new Error('TIP-403 compound policy components mismatch.')
  if (policy.senderPolicyId !== alwaysAllowPolicyId)
    throw new Error('TIP-403 sender policy is not always allow.')
  if (policy.recipientPolicyId !== policy.mintRecipientPolicyId)
    throw new Error('TIP-403 recipient and mint-recipient policies must match.')
  if (simplePolicy[0] !== 0)
    throw new Error('TIP-403 eligibility policy is not a whitelist.')
  if (!isAddressEqual(simplePolicy[1], accessAdministrator))
    throw new Error('TIP-403 access administrator mismatch.')
  const unauthorized = memberResults.find(
    (result) => !result.recipient || !result.mintRecipient,
  )
  if (unauthorized)
    throw new Error(
      `Required TIP-403 member is unauthorized: ${unauthorized.member}`,
    )
}

export namespace validateExitSafePolicy {
  export type Args = {
    /** Expected eligibility policy administrator. */
    accessAdministrator: Address
    /** Expected exit-safe policy IDs. */
    policy: ExitSafePolicy
    /** Addresses that must be eligible to receive or be minted Earn shares. */
    requiredMembers: readonly Address[]
    /** Earn share token. */
    shareToken: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  export type ReturnValue = void
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Deposits assets into a vault and mints Earn shares to `recipient`. The
 * transaction includes the required asset approval.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const hash = await Actions.earn.deposit(client, {
 *   assetAmount: 100_000_000n,
 *   shareAmount: 99_900_000n,
 *   slippageBps: 50,
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function deposit<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: deposit.Parameters<chain, account>,
): Promise<deposit.ReturnValue> {
  return deposit.inner(sendTransaction, client, parameters)
}

export namespace deposit {
  export type Args = {
    /** Assets to deposit; base units or `{ formatted, decimals? }` (asset decimals). */
    assetAmount: internal_Token.AmountInput
    /** Earn share recipient. @default `account.address` */
    recipient?: Address | undefined
    /** Vault address. */
    vault: Address
  } & OneOf<
    | {
        /** Minimum Earn share output to accept; must be greater than zero. */
        shareAmountMin: bigint
      }
    | {
        /** Quoted Earn share output; floored by `slippageBps`. */
        shareAmount: bigint
        /** Slippage tolerance in basis points under `shareAmount` (50 = 0.5%). */
        slippageBps: number
      }
  >
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** @internal Shared dispatch; reads the asset for the approval. */
  export async function inner<
    action extends typeof sendTransaction | typeof sendTransactionSync,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    action: action,
    client: Client<Transport, chain, account>,
    parameters: deposit.Parameters<chain, account>,
  ): Promise<ReturnType<action>> {
    const [args, assetToken] = await Promise.all([
      toDepositArgs(client, parameters as never),
      readContract(client, {
        abi: Abis.earnVault,
        address: parameters.vault,
        functionName: 'asset',
      }),
    ])
    return (await action(client, {
      ...parameters,
      calls: deposit.calls({ ...args, assetToken }),
    } as never)) as never
  }

  /**
   * Defines a deposit call without an approval. Provide token decimals for
   * formatted inputs and an explicit output bound because this builder performs no reads.
   *
   * @param parameters - Client (optional), followed by the call arguments.
   * @returns The call.
   */
  export function call<chain extends Chain | undefined>(
    ...parameters: CallParameters<call.Args, Client<Transport, chain>>
  ) {
    const [, args] = resolveCallParameters(parameters)
    const { recipient, vault } = args
    const shareAmountMin = (() => {
      if (args.shareAmountMin !== undefined) return args.shareAmountMin
      return EarnShares.minimumOutput(args.shareAmount, args.slippageBps)
    })()
    return defineCall({
      address: vault,
      abi: Abis.earnVault,
      functionName: 'deposit',
      args: [
        internal_Token.toBaseUnits(args.assetAmount, undefined),
        recipient,
        shareAmountMin,
      ],
    })
  }
  export namespace call {
    export type Args = {
      /** Assets to deposit; base units or `{ formatted, decimals? }` (asset decimals). */
      assetAmount: internal_Token.AmountInput
      /** Earn share recipient. */
      recipient: Address
      /** Vault address. */
      vault: Address
    } & OneOf<
      | {
          /** Minimum Earn share output to accept. */
          shareAmountMin: bigint
        }
      | {
          /** Quoted Earn share output; floored by `slippageBps`. */
          shareAmount: bigint
          /** Slippage tolerance in basis points under `shareAmount` (50 = 0.5%). */
          slippageBps: number
        }
    >
  }

  /**
   * Defines the asset approval and deposit calls for atomic execution. Pass
   * `assetToken` and token decimals explicitly because this builder performs no reads.
   *
   * @param args - Arguments.
   * @returns The calls.
   */
  export function calls(
    args: call.Args & {
      /** Asset token approved for the deposit. */
      assetToken: TokenId.TokenIdOrAddress
    },
  ) {
    const { assetToken, vault } = args
    const assetAmount = internal_Token.toBaseUnits(args.assetAmount, undefined)
    return [
      defineCall({
        address: TokenId.toAddress(assetToken),
        abi: Abis.tip20,
        functionName: 'approve',
        args: [vault, assetAmount],
      }),
      deposit.call({ ...args, assetAmount }),
    ]
  }

  /**
   * Extracts a `Deposited` event from the vault's logs.
   *
   * @param logs - Logs.
   * @param parameters - Parameters.
   * @returns The `Deposited` event.
   */
  export function extractEvent(
    logs: Log[],
    parameters: {
      /** Selects the first or last matching event. @default `'first'` */
      occurrence?: 'first' | 'last' | undefined
      vault: Address
    },
  ) {
    const { occurrence = 'first', vault } = parameters
    // Earn contracts are user-deployed: several adapters can emit the same
    // signature in one receipt, so filter by emitting address before decode.
    const parsed = parseEventLogs({
      abi: Abis.earnVault,
      eventName: 'Deposited',
      logs: logs.filter((log) => isAddressEqual(log.address, vault)),
    })
    const log = occurrence === 'last' ? parsed.at(-1) : parsed[0]
    if (!log) throw new Error('`Deposited` event not found.')
    return log
  }

  /**
   * Estimates gas for a deposit, assuming the vault has enough asset allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The gas estimate.
   */
  export async function estimateGas<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: deposit.Parameters<chain, account>,
  ): Promise<bigint> {
    return estimateContractGas(client, {
      ...pickWriteParameters(parameters as never),
      ...deposit.call(await toDepositArgs(client, parameters as never)),
    } as never)
  }

  /**
   * Simulates a deposit, assuming the vault has enough asset allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The simulation result and write request.
   */
  export async function simulate<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: deposit.Parameters<chain, account>,
  ): Promise<SimulateContractReturnType<typeof Abis.earnVault, 'deposit'>> {
    return simulateContract(client, {
      ...pickWriteParameters(parameters as never),
      ...deposit.call(await toDepositArgs(client, parameters as never)),
    } as never) as never
  }
}

/**
 * Deposits assets and returns the confirmed receipt and event data.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions, EarnShares } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const { shareAmount } = await Actions.earn.depositSync(client, {
 *   assetAmount: 100_000_000n,
 *   shareAmountMin: EarnShares.minimumOutput(99_900_000n, 50),
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function depositSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: depositSync.Parameters<chain, account>,
): Promise<depositSync.ReturnValue> {
  const { throwOnReceiptRevert = true, vault } = parameters
  const receipt = await deposit.inner(sendTransactionSync, client, {
    ...parameters,
    throwOnReceiptRevert,
  } as never)
  const { args } = deposit.extractEvent(receipt.logs, { vault })
  return {
    assetAmount: args.assets,
    caller: args.caller,
    receipt,
    recipient: args.receiver,
    shareAmount: args.earnShares,
  }
}

export namespace depositSync {
  export type Args = deposit.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = deposit.Parameters<chain, account> & WriteSyncParameters<chain, account>
  export type ReturnValue = Compute<{
    /** Assets deposited. */
    assetAmount: bigint
    /** Depositing caller. */
    caller: Address
    /** Transaction receipt. */
    receipt: TransactionReceipt
    /** Earn share recipient. */
    recipient: Address
    /** Earn shares minted. */
    shareAmount: bigint
  }>
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Deposits one asset amount across nested inner and outer Earn vaults
 * in one atomic Tempo transaction.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const hash = await Actions.earn.depositNested(client, {
 *   allocation: {
 *     assetAmount: 100_000_000n,
 *     innerAssetAmount: 40_000_000n,
 *     outerAssetAmount: 60_000_000n,
 *   },
 *   innerShareAmountMin: 39_500_000n,
 *   innerVault: '0x...',
 *   outerShareAmountMin: 59_000_000n,
 *   outerVault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - NestedEarnVaults, allocation, recipient, and per-leg output bounds.
 * @returns The transaction hash.
 */
export async function depositNested<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: depositNested.Parameters<chain, account>,
): Promise<depositNested.ReturnValue> {
  return depositNested.inner(sendTransaction, client, parameters)
}

export namespace depositNested {
  export type Args = NestedEarnVaults & {
    /** Asset split returned by {@link getNestedAllocation}. */
    allocation: NestedAllocation
    /** Minimum Inner Earn shares for the direct Inner leg; zero only for an empty leg. */
    innerShareAmountMin: bigint
    /** Minimum Outer Earn shares for the Outer leg; zero only for an empty leg. */
    outerShareAmountMin: bigint
    /** Earn share recipient. @default `account.address` */
    recipient?: Address | undefined
  }
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** @internal Shared dispatch for Inner and Outer deposit calls. */
  export async function inner<
    action extends typeof sendTransaction | typeof sendTransactionSync,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    action: action,
    client: Client<Transport, chain, account>,
    parameters: Parameters<chain, account>,
  ): Promise<ReturnType<action>> {
    const assetToken = await getNestedAsset(client, parameters)
    return (await action(client, {
      ...parameters,
      calls: calls({
        ...parameters,
        assetToken,
        recipient: resolveRecipient(client, parameters),
      }),
    } as never)) as never
  }

  /**
   * Defines the approvals and bounded Inner and Outer deposit calls. The
   * allocation is signed exactly; stale Outer capacity reverts the batch.
   */
  export function calls(
    args: Args & {
      /** Shared asset token approved to both nonempty legs. */
      assetToken: Address
      /** Earn share recipient. */
      recipient: Address
    },
  ) {
    const {
      allocation,
      assetToken,
      innerShareAmountMin,
      innerVault,
      outerShareAmountMin,
      outerVault,
      recipient,
    } = args
    validateNestedVaults({ innerVault, outerVault })
    validateNestedAllocation(allocation)
    validateNestedLeg(allocation.innerAssetAmount, innerShareAmountMin, 'Inner')
    validateNestedLeg(allocation.outerAssetAmount, outerShareAmountMin, 'Outer')
    return [
      ...(allocation.outerAssetAmount === 0n
        ? []
        : deposit.calls({
            assetAmount: allocation.outerAssetAmount,
            assetToken,
            recipient,
            shareAmountMin: outerShareAmountMin,
            vault: outerVault,
          })),
      ...(allocation.innerAssetAmount === 0n
        ? []
        : deposit.calls({
            assetAmount: allocation.innerAssetAmount,
            assetToken,
            recipient,
            shareAmountMin: innerShareAmountMin,
            vault: innerVault,
          })),
    ]
  }
}

/**
 * Deposits across nested Earn vaults and returns the confirmed receipt and per-vault
 * event data.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const result = await Actions.earn.depositNestedSync(client, {
 *   allocation: {
 *     assetAmount: 100_000_000n,
 *     innerAssetAmount: 40_000_000n,
 *     outerAssetAmount: 60_000_000n,
 *   },
 *   innerShareAmountMin: 39_500_000n,
 *   innerVault: '0x...',
 *   outerShareAmountMin: 59_000_000n,
 *   outerVault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - NestedEarnVaults deposit parameters.
 * @returns The confirmed receipt and each nonempty vault leg.
 */
export async function depositNestedSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: depositNestedSync.Parameters<chain, account>,
): Promise<depositNestedSync.ReturnValue> {
  const {
    allocation,
    innerVault,
    outerVault,
    throwOnReceiptRevert = true,
  } = parameters
  const receipt = await depositNested.inner(sendTransactionSync, client, {
    ...parameters,
    throwOnReceiptRevert,
  } as never)
  const toLeg = (vault: Address, occurrence: 'first' | 'last' = 'first') => {
    const { args } = deposit.extractEvent(receipt.logs, { occurrence, vault })
    return {
      assetAmount: args.assets,
      shareAmount: args.earnShares,
    }
  }
  return {
    // The Outer leg recursively emits from Inner first. Since the direct Inner
    // leg is dispatched last, its event is the final Inner-vault match.
    inner:
      allocation.innerAssetAmount === 0n
        ? undefined
        : toLeg(innerVault, 'last'),
    outer: allocation.outerAssetAmount === 0n ? undefined : toLeg(outerVault),
    receipt,
  }
}

export namespace depositNestedSync {
  export type Args = depositNested.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = depositNested.Parameters<chain, account> &
    WriteSyncParameters<chain, account>
  export type ReturnValue = {
    /** Confirmed direct Inner deposit, when the Inner leg was nonempty. */
    inner?: { assetAmount: bigint; shareAmount: bigint } | undefined
    /** Confirmed Outer deposit, when the Outer leg was nonempty. */
    outer?: { assetAmount: bigint; shareAmount: bigint } | undefined
    /** Confirmed atomic transaction receipt. */
    receipt: TransactionReceipt
  }
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Deposits venue shares into a vault and mints Earn shares to `recipient`.
 * The transaction includes the required venue share approval.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const hash = await Actions.earn.depositShares(client, {
 *   earnShareAmount: 499_000_000n,
 *   slippageBps: 30,
 *   vault: '0x...',
 *   venueShareAmount: 500_000_000n,
 *   venueShareToken: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function depositShares<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: depositShares.Parameters<chain, account>,
): Promise<depositShares.ReturnValue> {
  return depositShares.inner(sendTransaction, client, parameters)
}

export namespace depositShares {
  export type Args = {
    /** Venue shares to deposit, base units. */
    venueShareAmount: bigint
    /** Earn share recipient. @default `account.address` */
    recipient?: Address | undefined
    /** Vault address. */
    vault: Address
    /** Venue share token approved for the deposit. */
    venueShareToken: Address
  } & OneOf<
    | {
        /** Minimum Earn share output to accept; must be greater than zero. */
        earnShareAmountMin: bigint
      }
    | {
        /** Quoted Earn share output; floored by `slippageBps`. */
        earnShareAmount: bigint
        /** Slippage tolerance in basis points under `earnShareAmount` (50 = 0.5%). */
        slippageBps: number
      }
  >
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** @internal Shared dispatch; reads the engine for the approval. */
  export async function inner<
    action extends typeof sendTransaction | typeof sendTransactionSync,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    action: action,
    client: Client<Transport, chain, account>,
    parameters: depositShares.Parameters<chain, account>,
  ): Promise<ReturnType<action>> {
    const engine = await readContract(client, {
      abi: Abis.earnVault,
      address: parameters.vault,
      functionName: 'engine',
    })
    return (await action(client, {
      ...parameters,
      calls: depositShares.calls({
        ...toDepositSharesArgs(client, parameters as never),
        engine,
        venueShareToken: parameters.venueShareToken,
      }),
    } as never)) as never
  }

  /**
   * Defines a venue share deposit call without an approval. Provide an
   * explicit output bound because this builder performs no reads.
   *
   * @param parameters - Client (optional), followed by the call arguments.
   * @returns The call.
   */
  export function call<chain extends Chain | undefined>(
    ...parameters: CallParameters<call.Args, Client<Transport, chain>>
  ) {
    const [, args] = resolveCallParameters(parameters)
    const { recipient, vault, venueShareAmount } = args
    const earnShareAmountMin = (() => {
      if (args.earnShareAmountMin !== undefined) return args.earnShareAmountMin
      return EarnShares.minimumOutput(args.earnShareAmount, args.slippageBps)
    })()
    return defineCall({
      address: vault,
      abi: Abis.earnVault,
      functionName: 'depositVenueShares',
      args: [venueShareAmount, recipient, earnShareAmountMin],
    })
  }
  export namespace call {
    export type Args = {
      /** Venue shares to deposit, base units. */
      venueShareAmount: bigint
      /** Earn share recipient. */
      recipient: Address
      /** Vault address. */
      vault: Address
    } & OneOf<
      | {
          /** Minimum Earn share output to accept. */
          earnShareAmountMin: bigint
        }
      | {
          /** Quoted Earn share output; floored by `slippageBps`. */
          earnShareAmount: bigint
          /** Slippage tolerance in basis points under `earnShareAmount` (50 = 0.5%). */
          slippageBps: number
        }
    >
  }

  /**
   * Defines the venue share approval and deposit calls for atomic execution.
   * Pass the vault's current `engine` and `venueShareToken` explicitly.
   *
   * @param args - Arguments.
   * @returns The calls.
   */
  export function calls(
    args: call.Args & {
      /** Current vault engine that pulls the venue shares. */
      engine: Address
      /** Venue share token pulled by the engine. */
      venueShareToken: Address
    },
  ) {
    const { engine, venueShareAmount, venueShareToken } = args
    return [
      defineCall({
        address: venueShareToken,
        abi: Abis.tip20,
        functionName: 'approve',
        args: [engine, venueShareAmount],
      }),
      depositShares.call(args),
    ]
  }

  /**
   * Extracts a `VenueSharesDeposited` event from the vault's logs.
   *
   * @param logs - Logs.
   * @param parameters - Parameters.
   * @returns The `VenueSharesDeposited` event.
   */
  export function extractEvent(logs: Log[], parameters: { vault: Address }) {
    const { vault } = parameters
    // Earn contracts are user-deployed: several adapters can emit the same
    // signature in one receipt, so filter by emitting address before decode.
    const [log] = parseEventLogs({
      abi: Abis.earnVault,
      eventName: 'VenueSharesDeposited',
      logs: logs.filter((log) => isAddressEqual(log.address, vault)),
    })
    if (!log) throw new Error('`VenueSharesDeposited` event not found.')
    return log
  }

  /**
   * Estimates gas for a venue share deposit, assuming enough allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The gas estimate.
   */
  export async function estimateGas<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: depositShares.Parameters<chain, account>,
  ): Promise<bigint> {
    return estimateContractGas(client, {
      ...pickWriteParameters(parameters as never),
      ...depositShares.call(toDepositSharesArgs(client, parameters as never)),
    } as never)
  }

  /**
   * Simulates a venue share deposit, assuming enough allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The simulation result and write request.
   */
  export async function simulate<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: depositShares.Parameters<chain, account>,
  ): Promise<
    SimulateContractReturnType<typeof Abis.earnVault, 'depositVenueShares'>
  > {
    return simulateContract(client, {
      ...pickWriteParameters(parameters as never),
      ...depositShares.call(toDepositSharesArgs(client, parameters as never)),
    } as never) as never
  }
}

/**
 * Deposits venue shares and returns the confirmed receipt and event data.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions, EarnShares } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const { earnShareAmount } = await Actions.earn.depositSharesSync(client, {
 *   earnShareAmount: 499_000_000n,
 *   slippageBps: 30,
 *   vault: '0x...',
 *   venueShareAmount: 500_000_000n,
 *   venueShareToken: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function depositSharesSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: depositSharesSync.Parameters<chain, account>,
): Promise<depositSharesSync.ReturnValue> {
  const { throwOnReceiptRevert = true, vault } = parameters
  const receipt = await depositShares.inner(sendTransactionSync, client, {
    ...parameters,
    throwOnReceiptRevert,
  } as never)
  const { args } = depositShares.extractEvent(receipt.logs, { vault })
  return {
    caller: args.caller,
    earnShareAmount: args.earnShares,
    receipt,
    receivedVenueShareAmount: args.receivedEngineShares,
    recipient: args.receiver,
    venueShareAmount: args.requestedVenueShares,
  }
}

export namespace depositSharesSync {
  export type Args = depositShares.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = depositShares.Parameters<chain, account> &
    WriteSyncParameters<chain, account>
  export type ReturnValue = Compute<{
    /** Depositing caller. */
    caller: Address
    /** Earn shares minted. */
    earnShareAmount: bigint
    /** Transaction receipt. */
    receipt: TransactionReceipt
    /** Venue shares measured as received by the engine. */
    receivedVenueShareAmount: bigint
    /** Earn share recipient. */
    recipient: Address
    /** Venue shares requested for pull. */
    venueShareAmount: bigint
  }>
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Withdraws assets from a Zone and deposits them into a vault on the parent
 * chain. Use {@link privateDeposit.prepare} to build the encrypted callback.
 *
 * @example
 * ```ts
 * const prepared = await Actions.earn.privateDeposit.prepare(parentClient, {
 *   assetAmount: 100_000_000n,
 *   assetToken: '0x...',
 *   gateway: '0x...',
 *   recipient: '0x...',
 *   recoveryRecipient: '0x...',
 *   shareAmountMin: 99_500_000n,
 *   vault: '0x...',
 *   vaultAssetAmountMin: 99_000_000n,
 *   zoneId: 7,
 * })
 * const hash = await Actions.earn.privateDeposit(zoneClient, prepared)
 * ```
 *
 * @param client - Zone client.
 * @param parameters - Prepared deposit and transaction parameters.
 * @returns The transaction hash.
 */
export async function privateDeposit<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: privateDeposit.Parameters<chain, account>,
): Promise<privateDeposit.ReturnValue> {
  await assertPreparedZoneRequestChain(client, parameters)
  return zoneActions.requestWithdrawal(client, parameters)
}

export namespace privateDeposit {
  export type Args = prepare.ReturnValue
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  export type ErrorType = zoneActions.requestWithdrawal.ErrorType

  /**
   * Builds an encrypted Zone withdrawal that deposits into the selected vault
   * and returns the resulting shares to the Zone.
   *
   * @param client - Parent-chain client.
   * @param parameters - Deposit intent and recovery parameters.
   * @returns The prepared withdrawal and correlation data.
   */
  export async function prepare<chain extends Chain | undefined>(
    client: Client<Transport, chain>,
    parameters: prepare.Parameters,
  ): Promise<prepare.ReturnValue> {
    const chainId = client.chain?.id
    if (!chainId) throw new Error('`chain` is required.')
    const {
      actionId = Hex.random(32),
      assetAmount,
      callbackGas = zoneGatewayCallbackGas,
      fallbackRecipient = parameters.recoveryRecipient,
      gateway,
      portalAddress: portalAddress_,
      recipient,
      recoveryRecipient,
      returnMemo,
      vault,
      withdrawalMemo,
      zoneId,
    } = parameters
    const portalAddress = portalAddress_ ?? getPortalAddress(chainId, zoneId)
    const readParameters = pickReadParameters(parameters)
    const [fromBlock, config] = await Promise.all([
      getBlockNumber(client, { cacheTime: 0 }),
      getZoneGatewayConfig(client, {
        ...readParameters,
        flow: 0,
        gateway,
        vault,
        zoneId,
        zonePortal: portalAddress,
      }),
    ])
    const assetToken = parameters.assetToken ?? config.privateAsset
    if (!isAddressEqual(assetToken, config.privateAsset))
      throw new Error('`assetToken` must match the gateway private asset.')
    const { encrypted, keyIndex } =
      await zoneActions.encryptedDeposit.prepareRecipient(client, {
        ...readParameters,
        memo: returnMemo,
        portalAddress: config.zonePortal,
        recipient,
        zoneId: config.zoneId,
      })
    const shareAmountMin = resolveMinimumShareAmount(parameters)
    const data = encodeAbiParameters(Abis.earnRouterCallbackData, [
      {
        actionId,
        flow: 0,
        minEarnShares: shareAmountMin,
        minOutputAmount: 0n,
        minVaultAssets: parameters.vaultAssetAmountMin ?? assetAmount,
        zoneReturn: { encrypted, keyIndex, refundRecipient: recoveryRecipient },
      },
    ])
    return {
      actionId,
      amount: assetAmount,
      callbackGas,
      chainId,
      data,
      fallbackRecipient,
      fromBlock,
      memo: withdrawalMemo,
      to: gateway,
      token: assetToken,
      zoneId: config.zoneId,
    }
  }

  export namespace prepare {
    export type Parameters = Omit<ReadParameters, 'account'> & Args
    export type Args = PrivatePreparationParameters & {
      /** Assets withdrawn from the Zone, base units. */
      assetAmount: bigint
      /** Asset token withdrawn from the Zone. @default vault asset */
      assetToken?: Address | undefined
      /** Minimum vault assets accepted after swapping `assetToken`. @default `0n` */
      vaultAssetAmountMin?: bigint | undefined
    } & MinimumShareAmountParameters
    export type ReturnValue = PreparedZoneRequest
    export type ErrorType = BaseErrorType
  }

  /**
   * Defines the approval and Zone withdrawal calls for a prepared deposit.
   *
   * @param args - Prepared deposit arguments.
   * @returns The Zone withdrawal calls.
   */
  export function calls(args: Args) {
    return zoneActions.requestWithdrawal.calls(args)
  }
}

/**
 * Requests a private Zone deposit and waits for the Zone transaction receipt.
 * The receipt confirms withdrawal acceptance, not the parent-chain deposit.
 *
 * @param client - Zone client.
 * @param parameters - Prepared deposit and transaction parameters.
 * @returns The Zone transaction receipt and parent-chain withdrawal sender tag.
 */
export async function privateDepositSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: privateDepositSync.Parameters<chain, account>,
): Promise<privateDepositSync.ReturnValue> {
  await assertPreparedZoneRequestChain(client, parameters)
  return zoneActions.requestWithdrawalSync(client, parameters)
}

export namespace privateDepositSync {
  export type Args = privateDeposit.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = privateDeposit.Parameters<chain, account> &
    WriteSyncParameters<chain, account>
  export type ReturnValue = zoneActions.requestWithdrawalSync.ReturnValue
  export type ErrorType = zoneActions.requestWithdrawalSync.ErrorType
}

/**
 * Waits for a Zone gateway deposit to complete on the parent chain.
 *
 * @example
 * ```ts
 * const result = await Actions.earn.waitForPrivateDeposit(parentClient, {
 *   actionId: prepared.actionId,
 *   fromBlock: prepared.fromBlock,
 *   gateway: '0x...',
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Parent-chain client.
 * @param parameters - Prepared action correlation and polling parameters.
 * @returns The completed gateway deposit.
 */
export async function waitForPrivateDeposit<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: waitForPrivateDeposit.Parameters,
): Promise<waitForPrivateDeposit.ReturnType> {
  const {
    actionId,
    fromBlock,
    gateway,
    pollingInterval = client.pollingInterval,
    timeout = 60_000,
    vault,
  } = parameters
  const event = getAbiItem({
    abi: Abis.earnRouter,
    name: 'EarnDeposit',
  })
  const observerId = stringify([
    'waitForPrivateDeposit',
    client.uid,
    gateway,
    vault,
    actionId,
    fromBlock,
  ])
  const { promise, reject, resolve } =
    withResolvers<waitForPrivateDeposit.ReturnType>()

  let timer: ReturnType<typeof setTimeout> | undefined
  let unobserve: () => void
  const cleanup = () => {
    clearTimeout(timer)
    unobserve()
  }
  const resolve_ = (result: waitForPrivateDeposit.ReturnType) => {
    cleanup()
    resolve(result)
  }
  const reject_ = (error: unknown) => {
    cleanup()
    reject(error)
  }

  unobserve = observe(
    observerId,
    { reject: reject_, resolve: resolve_ },
    (emit) => {
      const unpoll = poll(
        async () => {
          try {
            const [log] = await getLogs(client, {
              address: gateway,
              args: { actionId, earnVault: vault },
              event,
              fromBlock,
              strict: true,
              toBlock: 'latest',
            })
            if (!log) return
            unpoll()
            emit.resolve({
              actionId: log.args.actionId,
              inputAmount: log.args.inputAmount,
              inputToken: log.args.inputToken,
              shares: log.args.earnShares,
              tempoBlockNumber: log.blockNumber,
              vaultAssets: log.args.vaultAssets,
              zoneDepositHash: log.args.zoneDepositHash,
            })
          } catch (error) {
            unpoll()
            emit.reject(error)
          }
        },
        { emitOnBegin: true, interval: pollingInterval },
      )

      return unpoll
    },
  )

  timer = timeout
    ? setTimeout(() => {
        reject_(new WaitForPrivateDepositTimeoutError({ actionId, gateway }))
      }, timeout)
    : undefined

  return await promise
}

export namespace waitForPrivateDeposit {
  export type Parameters = {
    /** Correlation id from {@link privateDeposit.prepare}. */
    actionId: Hex.Hex
    /** Lower bound for the parent-chain log scan. */
    fromBlock: bigint
    /** Zone gateway address. */
    gateway: Address
    /** Polling frequency in milliseconds. @default `client.pollingInterval` */
    pollingInterval?: number | undefined
    /** Timeout in milliseconds; `0` disables it. @default `60_000` */
    timeout?: number | undefined
    /** Vault address. */
    vault: Address
  }
  export type ReturnType = {
    /** Correlation id for the completed deposit. */
    actionId: Hex.Hex
    /** Tokens delivered to the gateway, base units. */
    inputAmount: bigint
    /** Token delivered to the gateway. */
    inputToken: Address
    /** Earn shares returned to the Zone. */
    shares: bigint
    /** Parent-chain block containing the gateway event. */
    tempoBlockNumber: bigint
    /** Vault assets deposited after any swap. */
    vaultAssets: bigint
    /** Encrypted return deposit hash. */
    zoneDepositHash: Hex.Hex
  }
  export type ErrorType =
    | GetLogsErrorType
    | ObserveErrorType
    | PollErrorType
    | WaitForPrivateDepositTimeoutErrorType
    | BaseErrorType
}

/**
 * Gets the vault's active fee configuration, pending fees, and fee baselines.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const feeState = await Actions.earn.getFeeState(client, {
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The active fee configuration, pending fees, and baselines.
 */
export async function getFeeState<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getFeeState.Parameters,
): Promise<getFeeState.ReturnValue> {
  const { recipient, vault, ...rest } = parameters
  const fees = await readContract(client, {
    ...rest,
    abi: Abis.earnVault,
    address: vault,
    functionName: 'earnFees',
  })
  const contracts = [
    defineCall({
      address: fees,
      abi: Abis.earnFees,
      functionName: 'currentFeeConfigId',
    }),
    defineCall({
      address: fees,
      abi: Abis.earnFees,
      functionName: 'feesActive',
    }),
    defineCall({
      address: fees,
      abi: Abis.earnFees,
      functionName: 'highWaterMark',
    }),
    defineCall({
      address: fees,
      abi: Abis.earnFees,
      functionName: 'previewAccruedFees',
    }),
    defineCall({
      address: fees,
      abi: Abis.earnFees,
      functionName: 'targetBase',
    }),
  ] as const
  // Stored configs are immutable per id, so a follow-up `feeConfig` read stays
  // consistent with the batched id.
  const feeConfig = async (configId: bigint) =>
    toFeeConfig(
      await readContract(client, {
        ...rest,
        abi: Abis.earnFees,
        address: fees,
        functionName: 'feeConfig',
        args: [configId],
      }),
    )
  if (recipient !== undefined) {
    const [configId, feesActive, highWaterMark, preview, targetBase, shares] =
      await multicall(client, {
        ...rest,
        allowFailure: false,
        contracts: [
          ...contracts,
          defineCall({
            address: fees,
            abi: Abis.earnFees,
            functionName: 'claimableEarnShares',
            args: [recipient],
          }),
        ],
        deployless: true,
      })
    return {
      claimableShares: shares,
      config: await feeConfig(configId),
      configId,
      feesActive,
      highWaterMark,
      preview: toFeePreview(preview),
      targetBase,
    }
  }
  const [configId, feesActive, highWaterMark, preview, targetBase] =
    await multicall(client, {
      ...rest,
      allowFailure: false,
      contracts,
      deployless: true,
    })
  return {
    config: await feeConfig(configId),
    configId,
    feesActive,
    highWaterMark,
    preview: toFeePreview(preview),
    targetBase,
  }
}

export namespace getFeeState {
  export type Args = {
    /** Optional fee recipient whose claimable Earn shares are included. */
    recipient?: Address | undefined
    /** Vault address. */
    vault: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  export type ReturnValue = {
    /** Claimable fee shares for `recipient`; present when provided. */
    claimableShares?: bigint | undefined
    /** Active fee configuration. */
    config: FeeConfig
    /** Active fee configuration id (starts at `1`). */
    configId: bigint
    /** Whether fees are configured and not emergency-disabled. */
    feesActive: boolean
    /** Post-fee high-water mark per Earn share. */
    highWaterMark: bigint
    /** Pending fee amounts. */
    preview: FeePreview
    /** Excess-return fee target per Earn share. */
    targetBase: bigint
  }
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/** Vault fee configuration. */
export type FeeConfig = {
  /** Optional excess-return fee over a growing target line. */
  excess: {
    /** Excess fee recipient. */
    account: Address
    /** Annual target growth rate in basis points. */
    annualTargetRateBps: number
    /** Whether the excess fee is active. */
    enabled: boolean
    /** Rate applied above the target in basis points. */
    excessFeeRateBps: number
  }
  /** Fixed fee recipients and their basis-point rates. */
  fixedFees: readonly { account: Address; rateBps: number }[]
}

/** Pending vault fee amounts. */
export type FeePreview = {
  /** Assets backing active Earn shares. */
  activeAssets: bigint
  /** Fee allocations in assets and Earn shares. */
  allocations: readonly {
    account: Address
    feeAssets: bigint
    feeShares: bigint
  }[]
  /** Excess-return fee portion, asset units. */
  excessFeeAssets: bigint
  /** Fixed fee portion, asset units. */
  fixedFeeAssets: bigint
  /** Accrual above the high-water mark, asset units. */
  positiveAccrualAssets: bigint
  /** Scaled asset value per Earn share after fees. */
  postFeeValuePerShare: bigint
  /** Scaled asset value per Earn share before fees. */
  preFeeValuePerShare: bigint
  /** Scaled excess-fee target per Earn share. */
  targetValuePerShare: bigint
  /** Total fee liability, asset units. */
  totalFeeAssets: bigint
  /** Earn shares minted to cover the total fee. */
  totalFeeShares: bigint
}

/**
 * Gets an account's asset and Earn share balances, allowances, and current
 * share value. The value includes fees.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const position = await Actions.earn.getPosition(client, {
 *   account: '0x...',
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The asset and Earn share balances, allowances, and value.
 */
export async function getPosition<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: getPosition.Parameters<account>,
): Promise<getPosition.ReturnValue> {
  const { account: account_ = client.account, vault, ...rest } = parameters
  if (!account_) throw new AccountNotFoundError()
  const account = parseAccount(account_).address
  const [assetToken, shareToken] = await multicall(client, {
    ...rest,
    allowFailure: false,
    contracts: [
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'asset',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'earnShare',
      }),
    ],
    deployless: true,
  })
  const [assetAllowance, assetBalance, shareAllowance, shareBalance] =
    await multicall(client, {
      ...rest,
      allowFailure: false,
      contracts: [
        defineCall({
          address: assetToken,
          abi: Abis.tip20,
          functionName: 'allowance',
          args: [account, vault],
        }),
        defineCall({
          address: assetToken,
          abi: Abis.tip20,
          functionName: 'balanceOf',
          args: [account],
        }),
        defineCall({
          address: shareToken,
          abi: Abis.tip20,
          functionName: 'allowance',
          args: [account, vault],
        }),
        defineCall({
          address: shareToken,
          abi: Abis.tip20,
          functionName: 'balanceOf',
          args: [account],
        }),
      ],
      deployless: true,
    })
  const value = await readContract(client, {
    ...rest,
    abi: Abis.earnVault,
    address: vault,
    args: [shareBalance],
    functionName: 'previewRedeem',
  })
  return {
    assetAllowance,
    assetBalance,
    assetToken,
    shareAllowance,
    shareBalance,
    shareToken,
    value,
  }
}

export namespace getPosition {
  export type Args<account extends Account | undefined = Account | undefined> =
    GetAccountParameter<account> & {
      /** Vault address. */
      vault: Address
    }
  export type Parameters<
    account extends Account | undefined = Account | undefined,
  > = Omit<ReadParameters, 'account'> & Args<account>
  export type ReturnValue = {
    /** Assets the vault may spend from the account. */
    assetAllowance: bigint
    /** Asset balance held by the account. */
    assetBalance: bigint
    /** Token accepted by the vault. */
    assetToken: Address
    /** Earn shares the vault may spend from the account. */
    shareAllowance: bigint
    /** Earn share balance held by the account. */
    shareBalance: bigint
    /** Token representing Earn shares. */
    shareToken: Address
    /** Current asset value of the Earn share balance, including fees. */
    value: bigint
  }
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/** Addresses that define one nested Earn composition. */
export type NestedEarnVaults = {
  /** Persistent inner Earn vault. */
  innerVault: Address
  /** Capped outer Earn vault backed by the inner vault. */
  outerVault: Address
}

/** Asset allocation across the inner and outer vaults. */
export type NestedAllocation = {
  /** Total assets requested. */
  assetAmount: bigint
  /** Assets routed directly to the inner vault. */
  innerAssetAmount: bigint
  /** Assets admitted to the outer vault. */
  outerAssetAmount: bigint
}

/**
 * Gets an account's unified nested Earn position.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const position = await Actions.earn.getNestedPosition(client, {
 *   account: '0x...',
 *   innerVault: '0x...',
 *   outerVault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Account and nested vaults.
 * @returns Both share positions and their aggregate asset value.
 */
export async function getNestedPosition<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: getNestedPosition.Parameters<account>,
): Promise<getNestedPosition.ReturnValue> {
  const { account, innerVault, outerVault, ...rest } = parameters
  validateNestedVaults({ innerVault, outerVault })
  const [inner, outer] = await Promise.all([
    getPosition(client, { ...rest, account, vault: innerVault } as never),
    getPosition(client, { ...rest, account, vault: outerVault } as never),
    validateNestedBinding(client, { innerVault, outerVault }),
  ])
  if (!isAddressEqual(inner.assetToken, outer.assetToken))
    throw new Error('Inner and outer vault assets do not match.')
  return {
    assetBalance: inner.assetBalance,
    assetToken: inner.assetToken,
    inner,
    outer,
    totalValue: inner.value + outer.value,
  }
}

export namespace getNestedPosition {
  export type Args<account extends Account | undefined = Account | undefined> =
    GetAccountParameter<account> & NestedEarnVaults
  export type Parameters<
    account extends Account | undefined = Account | undefined,
  > = Omit<ReadParameters, 'account'> & Args<account>
  export type ReturnValue = {
    /** Asset balance shared by both nested tiers. */
    assetBalance: bigint
    /** Token accepted by both nested vaults. */
    assetToken: Address
    /** Direct inner Earn position. */
    inner: getPosition.ReturnValue
    /** Capped outer Earn position. */
    outer: getPosition.ReturnValue
    /** Aggregate redeemable asset value across both share tokens. */
    totalValue: bigint
  }
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Gets the currently available inner and outer allocation for a deposit.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const allocation = await Actions.earn.getNestedAllocation(client, {
 *   assetAmount: 100_000_000n,
 *   outerVault: '0x...',
 *   recipient: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Requested assets, recipient, and outer vault.
 * @returns The live inner and outer asset split.
 */
export async function getNestedAllocation<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getNestedAllocation.Parameters,
): Promise<getNestedAllocation.ReturnValue> {
  const { assetAmount, outerVault, recipient, ...rest } = parameters
  if (assetAmount <= 0n)
    throw new Error('Nested asset amount must be greater than zero.')
  const outerAssetAmount = await readContract(client, {
    ...rest,
    ...getNestedAllocation.call({ assetAmount, outerVault, recipient }),
  })
  if (outerAssetAmount > assetAmount)
    throw new Error('Outer allocation exceeds the requested assets.')
  return {
    assetAmount,
    innerAssetAmount: assetAmount - outerAssetAmount,
    outerAssetAmount,
  }
}

export namespace getNestedAllocation {
  export type Args = {
    /** Assets to allocate, base units. */
    assetAmount: bigint
    /** Capped outer Earn vault. */
    outerVault: Address
    /** Earn share recipient whose public receiver cap applies. */
    recipient: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  export type ReturnValue = NestedAllocation
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** Defines the Outer vault allocation preview call. */
  export function call(args: Args) {
    const { assetAmount, outerVault, recipient } = args
    return defineCall({
      address: outerVault,
      abi: Abis.earnVault,
      args: [recipient, assetAmount],
      functionName: 'previewAllocation',
    })
  }
}

/**
 * Converts a quoted inner Earn share output into the corresponding outer Earn
 * share output.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const outerShareAmount = await Actions.earn.getOuterShareQuote(client, {
 *   innerShareAmount: 99_500_000n,
 *   outerVault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Inner share quote and outer vault.
 * @returns The fee-aware outer Earn share output.
 */
export async function getOuterShareQuote<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getOuterShareQuote.Parameters,
): Promise<getOuterShareQuote.ReturnValue> {
  const { innerShareAmount, outerVault, ...rest } = parameters
  if (innerShareAmount <= 0n)
    throw new Error('Inner share amount must be greater than zero.')
  return readContract(client, {
    ...rest,
    ...getOuterShareQuote.call({ innerShareAmount, outerVault }),
  })
}

export namespace getOuterShareQuote {
  export type Args = {
    /** Inner Earn shares expected from the outer asset leg. */
    innerShareAmount: bigint
    /** Capped outer Earn vault. */
    outerVault: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  export type ReturnValue = ReadContractReturnType<
    typeof Abis.earnVault,
    'previewDepositEngineShares',
    never
  >
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** Defines the Outer share quote call. */
  export function call(args: Args) {
    const { innerShareAmount, outerVault } = args
    return defineCall({
      address: outerVault,
      abi: Abis.earnVault,
      args: [innerShareAmount],
      functionName: 'previewDepositEngineShares',
    })
  }
}

/**
 * Gets fee-aware inner and outer redemption quotes for one nested position.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const quote = await Actions.earn.getNestedRedeemQuote(client, {
 *   innerShareAmount: 40_000_000n,
 *   innerVault: '0x...',
 *   outerShareAmount: 60_000_000n,
 *   outerVault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Nested vaults and exact share inputs.
 * @returns Independent inner and outer asset outputs and their sum.
 */
export async function getNestedRedeemQuote<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getNestedRedeemQuote.Parameters,
): Promise<getNestedRedeemQuote.ReturnValue> {
  const {
    innerShareAmount,
    innerVault,
    outerShareAmount,
    outerVault,
    ...rest
  } = parameters
  validateNestedVaults({ innerVault, outerVault })
  if (innerShareAmount < 0n || outerShareAmount < 0n)
    throw new Error('Nested share amounts cannot be negative.')
  if (innerShareAmount === 0n && outerShareAmount === 0n)
    throw new Error(
      'At least one nested share amount must be greater than zero.',
    )
  const [innerAssetAmount, outerAssetAmount] = await Promise.all([
    innerShareAmount === 0n
      ? 0n
      : getRedeemQuote(client, {
          ...rest,
          shareAmount: innerShareAmount,
          vault: innerVault,
        }),
    outerShareAmount === 0n
      ? 0n
      : getRedeemQuote(client, {
          ...rest,
          shareAmount: outerShareAmount,
          vault: outerVault,
        }),
    getNestedAsset(client, { innerVault, outerVault }),
  ])
  return {
    innerAssetAmount,
    outerAssetAmount,
    totalAssetAmount: innerAssetAmount + outerAssetAmount,
  }
}

export namespace getNestedRedeemQuote {
  export type Args = NestedEarnVaults & {
    /** Exact Inner Earn share input. */
    innerShareAmount: bigint
    /** Exact Outer Earn share input. */
    outerShareAmount: bigint
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  export type ReturnValue = {
    /** Assets quoted from the Inner share leg. */
    innerAssetAmount: bigint
    /** Assets quoted from the Outer share leg. */
    outerAssetAmount: bigint
    /** Aggregate quoted asset output. */
    totalAssetAmount: bigint
  }
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Gets the inner Earn shares returned by in-kind outer unwrapping.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const innerShareAmount = await Actions.earn.getUnwrapQuote(
 *   client,
 *   {
 *     outerShareAmount: 100_000_000n,
 *     outerVault: '0x...',
 *   },
 * )
 * ```
 *
 * @param client - Client.
 * @param parameters - Exact outer shares and outer vault.
 * @returns The fee-aware inner Earn share output.
 */
export async function getUnwrapQuote<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getUnwrapQuote.Parameters,
): Promise<getUnwrapQuote.ReturnValue> {
  const { outerShareAmount, outerVault, ...rest } = parameters
  if (outerShareAmount <= 0n)
    throw new Error('Outer share amount must be greater than zero.')
  return readContract(client, {
    ...rest,
    ...getUnwrapQuote.call({ outerShareAmount, outerVault }),
  })
}

export namespace getUnwrapQuote {
  export type Args = {
    /** Exact outer Earn share input. */
    outerShareAmount: bigint
    /** Capped outer Earn vault. */
    outerVault: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  export type ReturnValue = ReadContractReturnType<
    typeof Abis.earnVault,
    'previewRedeemVenueShares',
    never
  >
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** Defines the in-kind Outer unwrapping quote call. */
  export function call(args: Args) {
    const { outerShareAmount, outerVault } = args
    return defineCall({
      address: outerVault,
      abi: Abis.earnVault,
      args: [outerShareAmount],
      functionName: 'previewRedeemVenueShares',
    })
  }
}

/**
 * Gets the asset output for an exact Earn share input, including fees.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const assetAmount = await Actions.earn.getRedeemQuote(client, {
 *   shareAmount: 100_000_000n,
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The asset output, including fees.
 */
export async function getRedeemQuote<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getRedeemQuote.Parameters,
): Promise<getRedeemQuote.ReturnValue> {
  const { shareAmount, vault, ...rest } = parameters
  return readContract(client, {
    ...rest,
    ...getRedeemQuote.call({ shareAmount, vault }),
  })
}

export namespace getRedeemQuote {
  export type Args = {
    /** Exact Earn share input, base units. */
    shareAmount: bigint
    /** Vault address. */
    vault: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  /** Asset output, including fees. */
  export type ReturnValue = ReadContractReturnType<
    typeof Abis.earnVault,
    'previewRedeem',
    never
  >
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /**
   * Defines a call to the vault's `previewRedeem` function.
   *
   * Can be passed as a parameter to:
   * - [`estimateContractGas`](https://viem.sh/docs/contract/estimateContractGas): estimate the gas cost of the call
   * - [`multicall`](https://viem.sh/docs/contract/multicall): batch the call with other contract reads
   * - [`simulateContract`](https://viem.sh/docs/contract/simulateContract): simulate the call
   *
   * @example
   * ```ts
   * import { Actions } from 'viem/tempo'
   *
   * const call = Actions.earn.getRedeemQuote.call({
   *   shareAmount: 100_000_000n,
   *   vault: '0x...',
   * })
   * ```
   *
   * @param args - Arguments.
   * @returns The call.
   */
  export function call(args: Args) {
    const { shareAmount, vault } = args
    return defineCall({
      address: vault,
      abi: Abis.earnVault,
      args: [shareAmount],
      functionName: 'previewRedeem',
    })
  }
}

/**
 * Gets the vault's addresses, configuration, accounting state, and supported
 * actions. Throws {@link GetVaultEngineChangedError} if its engine changes mid-read.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const vault = await Actions.earn.getVault(client, {
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The vault state and metadata.
 */
export async function getVault<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getVault.Parameters,
): Promise<getVault.ReturnValue> {
  const { vault, ...rest } = parameters
  const [engine, fees] = await Promise.all([
    readContract(client, {
      ...rest,
      abi: Abis.earnVault,
      address: vault,
      functionName: 'engine',
    }),
    readContract(client, {
      ...rest,
      abi: Abis.earnVault,
      address: vault,
      functionName: 'earnFees',
    }),
  ])
  const [
    assetToken,
    engine_,
    shareToken,
    operator,
    emergencyGuardian,
    asyncJanitor,
    engineMigrationMode,
    depositsPaused,
    engineShares,
    shareSupply,
    isSynced,
    pendingRedeemCount,
    feesActive,
    totalAssets,
    name,
    symbol,
    asyncRedeem,
    exactWithdraw,
    inKindDeposit,
    syncRedeem,
  ] = await multicall(client, {
    ...rest,
    allowFailure: false,
    contracts: getVault.calls({ engine, fees, vault }),
    deployless: true,
  })
  if (!isAddressEqual(engine, engine_))
    throw new GetVaultEngineChangedError({ vault })
  return {
    assetToken,
    asyncJanitor,
    capabilities: { asyncRedeem, exactWithdraw, inKindDeposit, syncRedeem },
    depositsPaused,
    emergencyGuardian,
    engine: { address: engine_, name, symbol, totalAssets },
    // `EngineMigrationMode`: 0 = UserOnly, 1 = OperatorEnabled.
    engineMigrationMode:
      engineMigrationMode === 0 ? 'userOnly' : 'operatorEnabled',
    engineShares,
    feesActive,
    isSynced,
    operator,
    pendingRedeemCount,
    shareSupply,
    shareToken,
  }
}

export namespace getVault {
  export type Args = {
    /** Vault address. */
    vault: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  export type ReturnValue = {
    /** Token accepted by the vault. */
    assetToken: Address
    /** Address allowed to cancel queued redemptions; zero when disabled. */
    asyncJanitor: Address
    /** Actions supported by the current venue integration. */
    capabilities: {
      /** Queued redemptions. */
      asyncRedeem: boolean
      /** Exact asset withdrawals. */
      exactWithdraw: boolean
      /** Venue share deposits. */
      inKindDeposit: boolean
      /** Immediate redemptions. */
      syncRedeem: boolean
    }
    /** Whether new deposits are paused. */
    depositsPaused: boolean
    /** Address allowed to pause deposits; zero when disabled. */
    emergencyGuardian: Address
    /** Current venue integration. */
    engine: {
      /** Integration address. */
      address: Address
      /** Engine display name. */
      name: string
      /** Engine display symbol. */
      symbol: string
      /** Asset value of the active backing. */
      totalAssets: bigint
    }
    /** Whether only users may change the venue integration. */
    engineMigrationMode: 'operatorEnabled' | 'userOnly'
    /** Venue shares held for the vault. */
    engineShares: bigint
    /** Whether fees are configured and not emergency-disabled. */
    feesActive: boolean
    /** Whether Earn share supply matches its asset backing. */
    isSynced: boolean
    /** Vault governance address. */
    operator: Address
    /** Open queued redemptions. */
    pendingRedeemCount: bigint
    /** Active Earn share supply. */
    shareSupply: bigint
    /** Token representing Earn shares. */
    shareToken: Address
  }
  // TODO: exhaustive error type
  export type ErrorType = GetVaultEngineChangedErrorType | BaseErrorType

  /**
   * Defines the reads used by {@link getVault}. Pass the current engine and
   * fee contract addresses.
   *
   * @param args - Arguments.
   * @returns The calls.
   */
  export function calls(args: Args & { engine: Address; fees: Address }) {
    const { engine, fees, vault } = args
    return [
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'asset',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'engine',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'earnShare',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'operator',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'emergencyGuardian',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'asyncJanitor',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'engineMigrationMode',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'depositsPaused',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'engineShares',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'totalEarnShares',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'isAccountingAligned',
      }),
      defineCall({
        address: vault,
        abi: Abis.earnVault,
        functionName: 'openRedeemRequestCount',
      }),
      defineCall({
        address: fees,
        abi: Abis.earnFees,
        functionName: 'feesActive',
      }),
      defineCall({
        address: engine,
        abi: Abis.earnEngine,
        functionName: 'totalAssets',
      }),
      defineCall({
        address: engine,
        abi: Abis.earnEngine,
        functionName: 'name',
      }),
      defineCall({
        address: engine,
        abi: Abis.earnEngine,
        functionName: 'symbol',
      }),
      defineCall({
        address: engine,
        abi: Abis.earnEngine,
        functionName: 'supportsInterface',
        args: [interfaceIds.asyncRedeem],
      }),
      defineCall({
        address: engine,
        abi: Abis.earnEngine,
        functionName: 'supportsInterface',
        args: [interfaceIds.exactWithdraw],
      }),
      defineCall({
        address: engine,
        abi: Abis.earnEngine,
        functionName: 'supportsInterface',
        args: [interfaceIds.inKindDeposit],
      }),
      defineCall({
        address: engine,
        abi: Abis.earnEngine,
        functionName: 'supportsInterface',
        args: [interfaceIds.syncRedeem],
      }),
    ] as const
  }
}

/**
 * Gets the Earn shares required for an exact asset output, including fees
 * and ceiling rounding.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const shareAmount = await Actions.earn.getWithdrawQuote(client, {
 *   assetAmount: 250_000_000n,
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The required Earn share input, ceiling-rounded.
 */
export async function getWithdrawQuote<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: getWithdrawQuote.Parameters,
): Promise<getWithdrawQuote.ReturnValue> {
  const { assetAmount, vault, ...rest } = parameters
  return readContract(client, {
    ...rest,
    ...getWithdrawQuote.call({ assetAmount, vault }),
  })
}

export namespace getWithdrawQuote {
  export type Args = {
    /** Exact asset output, base units. */
    assetAmount: bigint
    /** Vault address. */
    vault: Address
  }
  export type Parameters = Omit<ReadParameters, 'account'> & Args
  /** Required Earn share input, ceiling-rounded. */
  export type ReturnValue = ReadContractReturnType<
    typeof Abis.earnVault,
    'previewWithdraw',
    never
  >
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /**
   * Defines a call to the vault's `previewWithdraw` function.
   *
   * Can be passed as a parameter to:
   * - [`estimateContractGas`](https://viem.sh/docs/contract/estimateContractGas): estimate the gas cost of the call
   * - [`multicall`](https://viem.sh/docs/contract/multicall): batch the call with other contract reads
   * - [`simulateContract`](https://viem.sh/docs/contract/simulateContract): simulate the call
   *
   * @example
   * ```ts
   * import { Actions } from 'viem/tempo'
   *
   * const call = Actions.earn.getWithdrawQuote.call({
   *   assetAmount: 250_000_000n,
   *   vault: '0x...',
   * })
   * ```
   *
   * @param args - Arguments.
   * @returns The call.
   */
  export function call(args: Args) {
    const { assetAmount, vault } = args
    return defineCall({
      address: vault,
      abi: Abis.earnVault,
      args: [assetAmount],
      functionName: 'previewWithdraw',
    })
  }
}

/**
 * Redeems Earn shares for assets sent to `recipient`. The transaction
 * includes the required Earn share approval.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const hash = await Actions.earn.redeem(client, {
 *   shareAmount: 100_000_000n,
 *   slippageBps: 50,
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function redeem<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: redeem.Parameters<chain, account>,
): Promise<redeem.ReturnValue> {
  return redeem.inner(sendTransaction, client, parameters)
}

export namespace redeem {
  export type Args = {
    /** Earn shares to redeem; base units or `{ formatted, decimals? }`. */
    shareAmount: internal_Token.AmountInput
    /** Asset recipient. @default `account.address` */
    recipient?: Address | undefined
    /** Vault address. */
    vault: Address
  } & OneOf<
    | {
        /** Minimum asset output to accept; must be greater than zero. */
        assetAmountMin: bigint
      }
    | {
        /** Slippage tolerance in basis points under a live {@link getRedeemQuote} (50 = 0.5%). */
        slippageBps: number
      }
    | {
        /** Quoted asset output; floored by `slippageBps`. */
        assetAmount: bigint
        /** Slippage tolerance in basis points under `assetAmount` (50 = 0.5%). */
        slippageBps: number
      }
  >
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** @internal Shared dispatch; reads the Earn share token for the approval. */
  export async function inner<
    action extends typeof sendTransaction | typeof sendTransactionSync,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    action: action,
    client: Client<Transport, chain, account>,
    parameters: redeem.Parameters<chain, account>,
  ): Promise<ReturnType<action>> {
    const [args, shareToken] = await Promise.all([
      toRedeemArgs(client, parameters as never),
      readContract(client, {
        abi: Abis.earnVault,
        address: parameters.vault,
        functionName: 'earnShare',
      }),
    ])
    return (await action(client, {
      ...parameters,
      calls: redeem.calls({ ...args, shareToken }),
    } as never)) as never
  }

  /**
   * Defines a redeem call without an approval. Provide Earn share decimals
   * for formatted inputs and an explicit output bound because this builder performs no reads.
   *
   * @param parameters - Client (optional), followed by the call arguments.
   * @returns The call.
   */
  export function call<chain extends Chain | undefined>(
    ...parameters: CallParameters<call.Args, Client<Transport, chain>>
  ) {
    const [, args] = resolveCallParameters(parameters)
    const { recipient, vault } = args
    const assetAmountMin = (() => {
      if (args.assetAmountMin !== undefined) return args.assetAmountMin
      return EarnShares.minimumOutput(args.assetAmount, args.slippageBps)
    })()
    return defineCall({
      address: vault,
      abi: Abis.earnVault,
      functionName: 'redeem',
      args: [
        internal_Token.toBaseUnits(args.shareAmount, undefined),
        recipient,
        assetAmountMin,
      ],
    })
  }
  export namespace call {
    export type Args = {
      /** Earn shares to redeem; base units or `{ formatted, decimals? }`. */
      shareAmount: internal_Token.AmountInput
      /** Asset recipient. */
      recipient: Address
      /** Vault address. */
      vault: Address
    } & OneOf<
      | {
          /** Minimum asset output to accept. */
          assetAmountMin: bigint
        }
      | {
          /** Quoted asset output; floored by `slippageBps`. */
          assetAmount: bigint
          /** Slippage tolerance in basis points under `assetAmount` (50 = 0.5%). */
          slippageBps: number
        }
    >
  }

  /**
   * Defines the Earn share approval and redeem calls for atomic execution.
   * Pass `shareToken` explicitly because this builder performs no reads.
   *
   * @param args - Arguments.
   * @returns The calls.
   */
  export function calls(
    args: call.Args & {
      /** Earn share token approved for the redemption. */
      shareToken: Address
    },
  ) {
    const { shareToken, vault } = args
    const shareAmount = internal_Token.toBaseUnits(args.shareAmount, undefined)
    return [
      defineCall({
        address: shareToken,
        abi: Abis.tip20,
        functionName: 'approve',
        args: [vault, shareAmount],
      }),
      redeem.call({ ...args, shareAmount }),
    ]
  }

  /**
   * Extracts a `Redeemed` event from the vault's logs.
   *
   * @param logs - Logs.
   * @param parameters - Parameters.
   * @returns The `Redeemed` event.
   */
  export function extractEvent(
    logs: Log[],
    parameters: {
      /** Selects the first or last matching event. @default `'first'` */
      occurrence?: 'first' | 'last' | undefined
      vault: Address
    },
  ) {
    const { occurrence = 'first', vault } = parameters
    // Earn contracts are user-deployed: several adapters can emit the same
    // signature in one receipt, so filter by emitting address before decode.
    const parsed = parseEventLogs({
      abi: Abis.earnVault,
      eventName: 'Redeemed',
      logs: logs.filter((log) => isAddressEqual(log.address, vault)),
    })
    const log = occurrence === 'last' ? parsed.at(-1) : parsed[0]
    if (!log) throw new Error('`Redeemed` event not found.')
    return log
  }

  /**
   * Estimates gas for a redemption, assuming enough Earn share allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The gas estimate.
   */
  export async function estimateGas<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: redeem.Parameters<chain, account>,
  ): Promise<bigint> {
    return estimateContractGas(client, {
      ...pickWriteParameters(parameters as never),
      ...redeem.call(await toRedeemArgs(client, parameters as never)),
    } as never)
  }

  /**
   * Simulates a redemption, assuming enough Earn share allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The simulation result and write request.
   */
  export async function simulate<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: redeem.Parameters<chain, account>,
  ): Promise<SimulateContractReturnType<typeof Abis.earnVault, 'redeem'>> {
    return simulateContract(client, {
      ...pickWriteParameters(parameters as never),
      ...redeem.call(await toRedeemArgs(client, parameters as never)),
    } as never) as never
  }
}

/**
 * Redeems Earn shares and returns the confirmed receipt and event data.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const { assetAmount } = await Actions.earn.redeemSync(client, {
 *   assetAmountMin: 99_500_000n,
 *   shareAmount: 100_000_000n,
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function redeemSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: redeemSync.Parameters<chain, account>,
): Promise<redeemSync.ReturnValue> {
  const { throwOnReceiptRevert = true, vault } = parameters
  const receipt = await redeem.inner(sendTransactionSync, client, {
    ...parameters,
    throwOnReceiptRevert,
  } as never)
  const { args } = redeem.extractEvent(receipt.logs, { vault })
  return {
    assetAmount: args.assets,
    caller: args.caller,
    receipt,
    recipient: args.receiver,
    shareAmount: args.earnShares,
  }
}

export namespace redeemSync {
  export type Args = redeem.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = redeem.Parameters<chain, account> & WriteSyncParameters<chain, account>
  export type ReturnValue = Compute<{
    /** Assets paid out. */
    assetAmount: bigint
    /** Redeeming caller. */
    caller: Address
    /** Transaction receipt. */
    receipt: TransactionReceipt
    /** Asset recipient. */
    recipient: Address
    /** Earn shares burned. */
    shareAmount: bigint
  }>
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Redeems inner and outer Earn shares in one atomic Tempo transaction.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const hash = await Actions.earn.redeemNested(client, {
 *   innerAssetAmount: 40_000_000n,
 *   innerShareAmount: 40_000_000n,
 *   innerVault: '0x...',
 *   outerAssetAmount: 60_000_000n,
 *   outerShareAmount: 60_000_000n,
 *   outerVault: '0x...',
 *   slippageBps: 50,
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Nested shares, recipient, and per-leg output bounds.
 * @returns The transaction hash.
 */
export async function redeemNested<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: redeemNested.Parameters<chain, account>,
): Promise<redeemNested.ReturnValue> {
  return redeemNested.inner(sendTransaction, client, parameters)
}

export namespace redeemNested {
  export type Args = NestedEarnVaults & {
    /** Exact Inner Earn shares to redeem. */
    innerShareAmount: bigint
    /** Exact Outer Earn shares to redeem. */
    outerShareAmount: bigint
    /** Asset recipient. @default `account.address` */
    recipient?: Address | undefined
  } & OneOf<
      | {
          /** Minimum Inner asset output; zero only for an empty Inner leg. */
          innerAssetAmountMin: bigint
          /** Minimum Outer asset output; zero only for an empty Outer leg. */
          outerAssetAmountMin: bigint
        }
      | {
          /** Quoted Inner asset output; zero only for an empty Inner leg. */
          innerAssetAmount: bigint
          /** Quoted Outer asset output; zero only for an empty Outer leg. */
          outerAssetAmount: bigint
          /** Slippage tolerance applied independently to both nonempty legs. */
          slippageBps: number
        }
    >
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** @internal Shared dispatch for Inner and Outer redemption calls. */
  export async function inner<
    action extends typeof sendTransaction | typeof sendTransactionSync,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    action: action,
    client: Client<Transport, chain, account>,
    parameters: Parameters<chain, account>,
  ): Promise<ReturnType<action>> {
    const [innerShareToken, outerShareToken] = await Promise.all([
      readContract(client, {
        abi: Abis.earnVault,
        address: parameters.innerVault,
        functionName: 'earnShare',
      }),
      readContract(client, {
        abi: Abis.earnVault,
        address: parameters.outerVault,
        functionName: 'earnShare',
      }),
      getNestedAsset(client, parameters),
    ])
    return (await action(client, {
      ...parameters,
      calls: calls({
        ...parameters,
        innerShareToken,
        outerShareToken,
        recipient: resolveRecipient(client, parameters),
      }),
    } as never)) as never
  }

  /** Defines the approvals and bounded Inner and Outer redemption calls. */
  export function calls(
    args: Args & {
      /** Inner Earn share token. */
      innerShareToken: Address
      /** Outer Earn share token. */
      outerShareToken: Address
      /** Asset recipient. */
      recipient: Address
    },
  ) {
    const {
      innerShareAmount,
      innerShareToken,
      innerVault,
      outerShareAmount,
      outerShareToken,
      outerVault,
      recipient,
    } = args
    validateNestedVaults({ innerVault, outerVault })
    const { innerAssetAmountMin, outerAssetAmountMin } =
      nestedRedeemMinimums(args)
    validateNestedLeg(innerShareAmount, innerAssetAmountMin, 'Inner')
    validateNestedLeg(outerShareAmount, outerAssetAmountMin, 'Outer')
    if (innerShareAmount === 0n && outerShareAmount === 0n)
      throw new Error(
        'At least one nested share amount must be greater than zero.',
      )
    return [
      ...(outerShareAmount === 0n
        ? []
        : redeem.calls({
            assetAmountMin: outerAssetAmountMin,
            recipient,
            shareAmount: outerShareAmount,
            shareToken: outerShareToken,
            vault: outerVault,
          })),
      ...(innerShareAmount === 0n
        ? []
        : redeem.calls({
            assetAmountMin: innerAssetAmountMin,
            recipient,
            shareAmount: innerShareAmount,
            shareToken: innerShareToken,
            vault: innerVault,
          })),
    ]
  }
}

/**
 * Redeems a nested position and returns the confirmed receipt and per-vault
 * event data.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const result = await Actions.earn.redeemNestedSync(client, {
 *   innerAssetAmountMin: 39_500_000n,
 *   innerShareAmount: 40_000_000n,
 *   innerVault: '0x...',
 *   outerAssetAmountMin: 59_000_000n,
 *   outerShareAmount: 60_000_000n,
 *   outerVault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Nested redemption parameters.
 * @returns The confirmed receipt and each nonempty redemption leg.
 */
export async function redeemNestedSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: redeemNestedSync.Parameters<chain, account>,
): Promise<redeemNestedSync.ReturnValue> {
  const {
    innerShareAmount,
    innerVault,
    outerShareAmount,
    outerVault,
    throwOnReceiptRevert = true,
  } = parameters
  const receipt = await redeemNested.inner(sendTransactionSync, client, {
    ...parameters,
    throwOnReceiptRevert,
  } as never)
  const toLeg = (vault: Address, occurrence: 'first' | 'last' = 'first') => {
    const { args } = redeem.extractEvent(receipt.logs, { occurrence, vault })
    return {
      assetAmount: args.assets,
      shareAmount: args.earnShares,
    }
  }
  return {
    // The Outer leg recursively emits from Inner first. The user's direct Inner
    // redemption is the final Inner-vault match.
    inner: innerShareAmount === 0n ? undefined : toLeg(innerVault, 'last'),
    outer: outerShareAmount === 0n ? undefined : toLeg(outerVault),
    receipt,
  }
}

export namespace redeemNestedSync {
  export type Args = redeemNested.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = redeemNested.Parameters<chain, account> &
    WriteSyncParameters<chain, account>
  export type ReturnValue = {
    /** Confirmed Inner redemption, when the Inner leg was nonempty. */
    inner?: { assetAmount: bigint; shareAmount: bigint } | undefined
    /** Confirmed Outer redemption, when the Outer leg was nonempty. */
    outer?: { assetAmount: bigint; shareAmount: bigint } | undefined
    /** Confirmed atomic transaction receipt. */
    receipt: TransactionReceipt
  }
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Converts outer Earn shares directly into their backing inner Earn shares
 * without redeeming the underlying asset.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const hash = await Actions.earn.unwrapNested(client, {
 *   innerShareAmount: 99_500_000n,
 *   outerShareAmount: 100_000_000n,
 *   outerVault: '0x...',
 *   slippageBps: 50,
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Outer shares, recipient, and inner share output bound.
 * @returns The transaction hash.
 */
export async function unwrapNested<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: unwrapNested.Parameters<chain, account>,
): Promise<unwrapNested.ReturnValue> {
  return unwrapNested.inner(sendTransaction, client, parameters)
}

export namespace unwrapNested {
  export type Args = {
    /** Exact Outer Earn shares to convert. */
    outerShareAmount: bigint
    /** Capped Outer Earn vault. */
    outerVault: Address
    /** Inner Earn share recipient. @default `account.address` */
    recipient?: Address | undefined
  } & OneOf<
    | {
        /** Minimum Inner Earn share output. */
        innerShareAmountMin: bigint
      }
    | {
        /** Quoted Inner Earn share output. */
        innerShareAmount: bigint
        /** Slippage tolerance under `innerShareAmount`. */
        slippageBps: number
      }
  >
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** @internal Shared dispatch for the holder-authorized unwrapping. */
  export async function inner<
    action extends typeof sendTransaction | typeof sendTransactionSync,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    action: action,
    client: Client<Transport, chain, account>,
    parameters: Parameters<chain, account>,
  ): Promise<ReturnType<action>> {
    const outerShareToken = await readContract(client, {
      abi: Abis.earnVault,
      address: parameters.outerVault,
      functionName: 'earnShare',
    })
    return (await action(client, {
      ...parameters,
      calls: calls({
        ...parameters,
        outerShareToken,
        recipient: resolveRecipient(client, parameters),
      }),
    } as never)) as never
  }

  /** Defines the Outer share approval and in-kind unwrapping calls. */
  export function calls(
    args: Args & {
      /** Outer Earn share token approved to the Outer vault. */
      outerShareToken: Address
      /** Inner Earn share recipient. */
      recipient: Address
    },
  ) {
    const { outerShareAmount, outerShareToken, outerVault, recipient } = args
    if (outerShareAmount <= 0n)
      throw new Error('Outer share amount must be greater than zero.')
    const innerShareAmountMin =
      args.innerShareAmountMin ??
      EarnShares.minimumOutput(args.innerShareAmount, args.slippageBps)
    if (innerShareAmountMin <= 0n)
      throw new Error('Minimum Inner share output must be greater than zero.')
    return [
      defineCall({
        address: outerShareToken,
        abi: Abis.tip20,
        args: [outerVault, outerShareAmount],
        functionName: 'approve',
      }),
      defineCall({
        address: outerVault,
        abi: Abis.earnVault,
        args: [outerShareAmount, recipient, innerShareAmountMin],
        functionName: 'redeemVenueShares',
      }),
    ]
  }

  /** Extracts the in-kind unwrapping event from the Outer vault logs. */
  export function extractEvent(
    logs: Log[],
    parameters: { outerVault: Address },
  ) {
    const [log] = parseEventLogs({
      abi: Abis.earnVault,
      eventName: 'VenueSharesRedeemed',
      logs: logs.filter((log) =>
        isAddressEqual(log.address, parameters.outerVault),
      ),
    })
    if (!log) throw new Error('`VenueSharesRedeemed` event not found.')
    return log
  }
}

/**
 * Converts outer shares into inner shares and returns the confirmed receipt
 * and unwrapping event data.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const result = await Actions.earn.unwrapNestedSync(client, {
 *   innerShareAmountMin: 99_000_000n,
 *   outerShareAmount: 100_000_000n,
 *   outerVault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Nested unwrapping parameters.
 * @returns The confirmed receipt and inner share output.
 */
export async function unwrapNestedSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: unwrapNestedSync.Parameters<chain, account>,
): Promise<unwrapNestedSync.ReturnValue> {
  const { outerVault, throwOnReceiptRevert = true } = parameters
  const receipt = await unwrapNested.inner(sendTransactionSync, client, {
    ...parameters,
    throwOnReceiptRevert,
  } as never)
  const { args } = unwrapNested.extractEvent(receipt.logs, { outerVault })
  return {
    innerShareAmount: args.venueShares,
    outerShareAmount: args.earnShares,
    receipt,
    recipient: args.receiver,
  }
}

export namespace unwrapNestedSync {
  export type Args = unwrapNested.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = unwrapNested.Parameters<chain, account> &
    WriteSyncParameters<chain, account>
  export type ReturnValue = {
    /** Inner Earn shares delivered. */
    innerShareAmount: bigint
    /** Outer Earn shares burned. */
    outerShareAmount: bigint
    /** Confirmed unwrapping receipt. */
    receipt: TransactionReceipt
    /** Inner Earn share recipient. */
    recipient: Address
  }
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

/**
 * Withdraws Earn shares from a Zone and redeems them on the parent chain. Use
 * {@link privateRedeem.prepare} to build the encrypted callback.
 *
 * @example
 * ```ts
 * const prepared = await Actions.earn.privateRedeem.prepare(parentClient, {
 *   gateway: '0x...',
 *   recipient: '0x...',
 *   recoveryRecipient: '0x...',
 *   shareAmount: 100_000_000n,
 *   slippageBps: 50,
 *   vault: '0x...',
 *   zoneId: 7,
 * })
 * const hash = await Actions.earn.privateRedeem(zoneClient, prepared)
 * ```
 *
 * @param client - Zone client.
 * @param parameters - Prepared redemption and transaction parameters.
 * @returns The transaction hash.
 */
export async function privateRedeem<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: privateRedeem.Parameters<chain, account>,
): Promise<privateRedeem.ReturnValue> {
  await assertPreparedZoneRequestChain(client, parameters)
  return zoneActions.requestWithdrawal(client, parameters)
}

export namespace privateRedeem {
  export type Args = prepare.ReturnValue
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  export type ErrorType = zoneActions.requestWithdrawal.ErrorType

  /**
   * Builds an encrypted Zone withdrawal that redeems Earn shares and returns
   * the resulting assets to the Zone.
   *
   * @param client - Parent-chain client.
   * @param parameters - Redemption intent and recovery parameters.
   * @returns The prepared withdrawal and correlation data.
   */
  export async function prepare<chain extends Chain | undefined>(
    client: Client<Transport, chain>,
    parameters: prepare.Parameters,
  ): Promise<prepare.ReturnValue> {
    const chainId = client.chain?.id
    if (!chainId) throw new Error('`chain` is required.')
    const {
      actionId = Hex.random(32),
      callbackGas = zoneGatewayCallbackGas,
      fallbackRecipient = parameters.recoveryRecipient,
      gateway,
      portalAddress: portalAddress_,
      recipient,
      recoveryRecipient,
      returnMemo,
      shareAmount,
      vault,
      withdrawalMemo,
      zoneId,
    } = parameters
    const portalAddress = portalAddress_ ?? getPortalAddress(chainId, zoneId)
    const readParameters = pickReadParameters(parameters)
    const [fromBlock, config] = await Promise.all([
      getBlockNumber(client, { cacheTime: 0 }),
      getZoneGatewayConfig(client, {
        ...readParameters,
        flow: 1,
        gateway,
        vault,
        zoneId,
        zonePortal: portalAddress,
      }),
    ])
    const assetToken = parameters.assetToken ?? config.privateAsset
    if (isAddressEqual(assetToken, config.shareToken))
      throw new Error('`assetToken` cannot be the Earn share token.')
    if (!isAddressEqual(assetToken, config.privateAsset))
      throw new Error('`assetToken` must match the gateway private asset.')

    const [{ encrypted, keyIndex }, assetAmountMin] = await Promise.all([
      zoneActions.encryptedDeposit.prepareRecipient(client, {
        ...readParameters,
        memo: returnMemo,
        portalAddress: config.zonePortal,
        recipient,
        zoneId: config.zoneId,
      }),
      (async () => {
        if (parameters.assetAmountMin !== undefined)
          return EarnShares.minimumOutput(parameters.assetAmountMin, 0)
        if (parameters.assetAmount !== undefined)
          return EarnShares.minimumOutput(
            parameters.assetAmount,
            parameters.slippageBps,
          )
        const assetAmount = await getRedeemQuote(client, {
          ...readParameters,
          shareAmount,
          vault: config.vault,
        })
        return EarnShares.minimumOutput(assetAmount, parameters.slippageBps)
      })(),
    ])
    const data = encodeAbiParameters(Abis.earnRouterCallbackData, [
      {
        actionId,
        flow: 1,
        minEarnShares: 0n,
        minOutputAmount: assetAmountMin,
        minVaultAssets: 1n,
        zoneReturn: { encrypted, keyIndex, refundRecipient: recoveryRecipient },
      },
    ])
    return {
      actionId,
      amount: shareAmount,
      callbackGas,
      chainId,
      data,
      fallbackRecipient,
      fromBlock,
      memo: withdrawalMemo,
      to: gateway,
      token: config.shareToken,
      zoneId: config.zoneId,
    }
  }

  export namespace prepare {
    export type Parameters = Omit<ReadParameters, 'account'> &
      PrivatePreparationParameters & {
        /** Earn shares withdrawn from the Zone, base units. */
        shareAmount: bigint
      } & (
        | ({
            /** Asset token returned to the Zone. @default vault asset */
            assetToken?: undefined
          } & OneOf<
            | {
                /** Minimum assets returned to the Zone. */
                assetAmountMin: bigint
              }
            | {
                /** Quoted assets returned to the Zone. */
                assetAmount: bigint
                /** Slippage tolerance under `assetAmount` (50 = 0.5%). */
                slippageBps: number
              }
            | {
                /** Slippage tolerance under a live vault quote (50 = 0.5%). */
                slippageBps: number
              }
          >)
        | ({
            /** Asset token returned to the Zone after a swap. */
            assetToken: Address
          } & MinimumAssetAmountParameters)
      )
    export type ReturnValue = PreparedZoneRequest
    export type ErrorType = BaseErrorType
  }

  /**
   * Defines the approval and Zone withdrawal calls for a prepared redemption.
   *
   * @param args - Prepared redemption arguments.
   * @returns The Zone withdrawal calls.
   */
  export function calls(args: Args) {
    return zoneActions.requestWithdrawal.calls(args)
  }
}

/**
 * Requests a private Zone redemption and waits for the Zone transaction
 * receipt. The receipt confirms withdrawal acceptance, not redemption.
 *
 * @param client - Zone client.
 * @param parameters - Prepared redemption and transaction parameters.
 * @returns The Zone transaction receipt and parent-chain withdrawal sender tag.
 */
export async function privateRedeemSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: privateRedeemSync.Parameters<chain, account>,
): Promise<privateRedeemSync.ReturnValue> {
  await assertPreparedZoneRequestChain(client, parameters)
  return zoneActions.requestWithdrawalSync(client, parameters)
}

export namespace privateRedeemSync {
  export type Args = privateRedeem.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = privateRedeem.Parameters<chain, account> &
    WriteSyncParameters<chain, account>
  export type ReturnValue = zoneActions.requestWithdrawalSync.ReturnValue
  export type ErrorType = zoneActions.requestWithdrawalSync.ErrorType
}

/**
 * Waits for a Zone gateway redemption to complete on the parent chain.
 *
 * @example
 * ```ts
 * const result = await Actions.earn.waitForPrivateRedeem(parentClient, {
 *   actionId: prepared.actionId,
 *   fromBlock: prepared.fromBlock,
 *   gateway: '0x...',
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Parent-chain client.
 * @param parameters - Prepared action correlation and polling parameters.
 * @returns The completed gateway redemption.
 */
export async function waitForPrivateRedeem<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: waitForPrivateRedeem.Parameters,
): Promise<waitForPrivateRedeem.ReturnType> {
  const {
    actionId,
    fromBlock,
    gateway,
    pollingInterval = client.pollingInterval,
    timeout = 60_000,
    vault,
  } = parameters
  const event = getAbiItem({
    abi: Abis.earnRouter,
    name: 'EarnRedeem',
  })
  const observerId = stringify([
    'waitForPrivateRedeem',
    client.uid,
    gateway,
    vault,
    actionId,
    fromBlock,
  ])
  const { promise, reject, resolve } =
    withResolvers<waitForPrivateRedeem.ReturnType>()

  let timer: ReturnType<typeof setTimeout> | undefined
  let unobserve: () => void
  const cleanup = () => {
    clearTimeout(timer)
    unobserve()
  }
  const resolve_ = (result: waitForPrivateRedeem.ReturnType) => {
    cleanup()
    resolve(result)
  }
  const reject_ = (error: unknown) => {
    cleanup()
    reject(error)
  }

  unobserve = observe(
    observerId,
    { reject: reject_, resolve: resolve_ },
    (emit) => {
      const unpoll = poll(
        async () => {
          try {
            const [log] = await getLogs(client, {
              address: gateway,
              args: { actionId, earnVault: vault },
              event,
              fromBlock,
              strict: true,
              toBlock: 'latest',
            })
            if (!log) return
            unpoll()
            emit.resolve({
              actionId: log.args.actionId,
              outputAmount: log.args.outputAmount,
              outputToken: log.args.outputToken,
              shares: log.args.earnShares,
              tempoBlockNumber: log.blockNumber,
              vaultAssets: log.args.vaultAssets,
              zoneDepositHash: log.args.zoneDepositHash,
            })
          } catch (error) {
            unpoll()
            emit.reject(error)
          }
        },
        { emitOnBegin: true, interval: pollingInterval },
      )

      return unpoll
    },
  )

  timer = timeout
    ? setTimeout(() => {
        reject_(new WaitForPrivateRedeemTimeoutError({ actionId, gateway }))
      }, timeout)
    : undefined

  return await promise
}

export namespace waitForPrivateRedeem {
  export type Parameters = {
    /** Correlation id from {@link privateRedeem.prepare}. */
    actionId: Hex.Hex
    /** Lower bound for the parent-chain log scan. */
    fromBlock: bigint
    /** Zone gateway address. */
    gateway: Address
    /** Polling frequency in milliseconds. @default `client.pollingInterval` */
    pollingInterval?: number | undefined
    /** Timeout in milliseconds; `0` disables it. @default `60_000` */
    timeout?: number | undefined
    /** Vault address. */
    vault: Address
  }
  export type ReturnType = {
    /** Correlation id for the completed redemption. */
    actionId: Hex.Hex
    /** Tokens returned to the Zone, base units. */
    outputAmount: bigint
    /** Token returned to the Zone. */
    outputToken: Address
    /** Earn shares redeemed. */
    shares: bigint
    /** Parent-chain block containing the gateway event. */
    tempoBlockNumber: bigint
    /** Vault assets produced before any swap. */
    vaultAssets: bigint
    /** Encrypted return deposit hash. */
    zoneDepositHash: Hex.Hex
  }
  export type ErrorType =
    | GetLogsErrorType
    | ObserveErrorType
    | PollErrorType
    | WaitForPrivateRedeemTimeoutErrorType
    | BaseErrorType
}

/**
 * Withdraws an exact asset amount to `recipient`, up to the specified Earn
 * share limit. The transaction includes the required Earn share approval;
 * use {@link redeem} for a full exit.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const hash = await Actions.earn.withdrawExact(client, {
 *   assetAmount: 40_000_000n,
 *   slippageBps: 50,
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction hash.
 */
export async function withdrawExact<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: withdrawExact.Parameters<chain, account>,
): Promise<withdrawExact.ReturnValue> {
  return withdrawExact.inner(sendTransaction, client, parameters)
}

export namespace withdrawExact {
  export type Args = {
    /** Exact assets to receive; base units or `{ formatted, decimals? }`. */
    assetAmount: internal_Token.AmountInput
    /** Asset recipient. @default `account.address` */
    recipient?: Address | undefined
    /** Vault address. */
    vault: Address
  } & OneOf<
    | {
        /** Maximum Earn share input to burn. */
        shareAmountMax: bigint
      }
    | {
        /** Slippage headroom above a live {@link getWithdrawQuote}, ceiling-rounded (50 = 0.5%). */
        slippageBps: number
      }
    | {
        /** Quoted Earn share input; raised by `slippageBps`. */
        shareAmount: bigint
        /** Slippage tolerance in basis points over `shareAmount` (50 = 0.5%). */
        slippageBps: number
      }
  >
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = WriteParameters<chain, account> & Args
  export type ReturnValue = SendTransactionReturnType
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType

  /** @internal Shared dispatch; reads the Earn share token for the approval. */
  export async function inner<
    action extends typeof sendTransaction | typeof sendTransactionSync,
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    action: action,
    client: Client<Transport, chain, account>,
    parameters: withdrawExact.Parameters<chain, account>,
  ): Promise<ReturnType<action>> {
    const [args, shareToken] = await Promise.all([
      toWithdrawExactArgs(client, parameters as never),
      readContract(client, {
        abi: Abis.earnVault,
        address: parameters.vault,
        functionName: 'earnShare',
      }),
    ])
    return (await action(client, {
      ...parameters,
      calls: withdrawExact.calls({ ...args, shareToken }),
    } as never)) as never
  }

  /**
   * Defines an exact withdrawal call without an approval. Provide asset
   * decimals and an explicit input limit because this builder performs no reads.
   *
   * @param parameters - Client (optional), followed by the call arguments.
   * @returns The call.
   */
  export function call<chain extends Chain | undefined>(
    ...parameters: CallParameters<call.Args, Client<Transport, chain>>
  ) {
    const [, args] = resolveCallParameters(parameters)
    const { recipient, vault } = args
    const shareAmountMax = (() => {
      if (args.shareAmountMax !== undefined) return args.shareAmountMax
      return maximumInput(args.shareAmount, args.slippageBps)
    })()
    return defineCall({
      address: vault,
      abi: Abis.earnVault,
      functionName: 'withdrawExact',
      args: [
        internal_Token.toBaseUnits(args.assetAmount, undefined),
        recipient,
        shareAmountMax,
      ],
    })
  }
  export namespace call {
    export type Args = {
      /** Exact assets to receive; base units or `{ formatted, decimals? }`. */
      assetAmount: internal_Token.AmountInput
      /** Asset recipient. */
      recipient: Address
      /** Vault address. */
      vault: Address
    } & OneOf<
      | {
          /** Maximum Earn share input to burn. */
          shareAmountMax: bigint
        }
      | {
          /** Quoted Earn share input; raised by `slippageBps`. */
          shareAmount: bigint
          /** Slippage tolerance in basis points over `shareAmount` (50 = 0.5%). */
          slippageBps: number
        }
    >
  }

  /**
   * Defines the Earn share approval and withdrawal calls for atomic
   * execution. Pass `shareToken` explicitly because this builder performs no reads.
   *
   * @param args - Arguments.
   * @returns The calls.
   */
  export function calls(
    args: call.Args & {
      /** Earn share token approved for the withdrawal. */
      shareToken: Address
    },
  ) {
    const { shareToken, vault } = args
    const assetAmount = internal_Token.toBaseUnits(args.assetAmount, undefined)
    const call = withdrawExact.call({ ...args, assetAmount })
    const [, , shareAmountMax] = call.args
    return [
      defineCall({
        address: shareToken,
        abi: Abis.tip20,
        functionName: 'approve',
        args: [vault, shareAmountMax],
      }),
      call,
    ]
  }

  /**
   * Extracts a `WithdrewExact` event from the vault's logs.
   *
   * @param logs - Logs.
   * @param parameters - Parameters.
   * @returns The `WithdrewExact` event.
   */
  export function extractEvent(logs: Log[], parameters: { vault: Address }) {
    const { vault } = parameters
    // Earn contracts are user-deployed: several adapters can emit the same
    // signature in one receipt, so filter by emitting address before decode.
    const [log] = parseEventLogs({
      abi: Abis.earnVault,
      eventName: 'WithdrewExact',
      logs: logs.filter((log) => isAddressEqual(log.address, vault)),
    })
    if (!log) throw new Error('`WithdrewExact` event not found.')
    return log
  }

  /**
   * Estimates gas for an exact withdrawal, assuming enough Earn share allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The gas estimate.
   */
  export async function estimateGas<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: withdrawExact.Parameters<chain, account>,
  ): Promise<bigint> {
    return estimateContractGas(client, {
      ...pickWriteParameters(parameters as never),
      ...withdrawExact.call(
        await toWithdrawExactArgs(client, parameters as never),
      ),
    } as never)
  }

  /**
   * Simulates an exact withdrawal, assuming enough Earn share allowance.
   *
   * @param client - Client.
   * @param parameters - Parameters.
   * @returns The simulation result and write request.
   */
  export async function simulate<
    chain extends Chain | undefined,
    account extends Account | undefined,
  >(
    client: Client<Transport, chain, account>,
    parameters: withdrawExact.Parameters<chain, account>,
  ): Promise<
    SimulateContractReturnType<typeof Abis.earnVault, 'withdrawExact'>
  > {
    return simulateContract(client, {
      ...pickWriteParameters(parameters as never),
      ...withdrawExact.call(
        await toWithdrawExactArgs(client, parameters as never),
      ),
    } as never) as never
  }
}

/**
 * Withdraws an exact asset amount and returns the confirmed receipt and event data.
 *
 * @example
 * ```ts
 * import { createClient, http } from 'viem'
 * import { privateKeyToAccount } from 'viem/accounts'
 * import { tempoModerato } from 'viem/chains'
 * import { Actions } from 'viem/tempo'
 *
 * const client = createClient({
 *   account: privateKeyToAccount('0x...'),
 *   chain: tempoModerato,
 *   transport: http(),
 * })
 *
 * const { shareAmount } = await Actions.earn.withdrawExactSync(client, {
 *   assetAmount: 40_000_000n,
 *   shareAmountMax: 40_200_000n,
 *   vault: '0x...',
 * })
 * ```
 *
 * @param client - Client.
 * @param parameters - Parameters.
 * @returns The transaction receipt and event data.
 */
export async function withdrawExactSync<
  chain extends Chain | undefined,
  account extends Account | undefined,
>(
  client: Client<Transport, chain, account>,
  parameters: withdrawExactSync.Parameters<chain, account>,
): Promise<withdrawExactSync.ReturnValue> {
  const { throwOnReceiptRevert = true, vault } = parameters
  const receipt = await withdrawExact.inner(sendTransactionSync, client, {
    ...parameters,
    throwOnReceiptRevert,
  } as never)
  const { args } = withdrawExact.extractEvent(receipt.logs, { vault })
  return {
    assetAmount: args.assets,
    caller: args.caller,
    receipt,
    recipient: args.receiver,
    shareAmount: args.earnSharesBurned,
  }
}

export namespace withdrawExactSync {
  export type Args = withdrawExact.Args
  export type Parameters<
    chain extends Chain | undefined = Chain | undefined,
    account extends Account | undefined = Account | undefined,
  > = withdrawExact.Parameters<chain, account> &
    WriteSyncParameters<chain, account>
  export type ReturnValue = Compute<{
    /** Exact assets received. */
    assetAmount: bigint
    /** Withdrawing caller. */
    caller: Address
    /** Transaction receipt. */
    receipt: TransactionReceipt
    /** Asset recipient. */
    recipient: Address
    /** Earn shares burned. */
    shareAmount: bigint
  }>
  // TODO: exhaustive error type
  export type ErrorType = BaseErrorType
}

type MinimumAssetAmountParameters = OneOf<
  | {
      /** Minimum assets returned to the Zone. */
      assetAmountMin: bigint
    }
  | {
      /** Quoted assets returned to the Zone. */
      assetAmount: bigint
      /** Slippage tolerance under `assetAmount` (50 = 0.5%). */
      slippageBps: number
    }
>

type MinimumShareAmountParameters = OneOf<
  | {
      /** Minimum Earn shares returned to the Zone. */
      shareAmountMin: bigint
    }
  | {
      /** Quoted Earn shares returned to the Zone. */
      shareAmount: bigint
      /** Slippage tolerance under `shareAmount` (50 = 0.5%). */
      slippageBps: number
    }
>

type PrivatePreparationParameters = {
  /** Optional caller-supplied correlation id. @default Random bytes32 */
  actionId?: Hex.Hex | undefined
  /** Gas reserved for the parent-chain callback. @default `10_000_000n` */
  callbackGas?: bigint | undefined
  /** Public recipient if the parent-chain callback fails. @default `recoveryRecipient` */
  fallbackRecipient?: Address | undefined
  /** Zone gateway address. */
  gateway: Address
  /** Source Zone portal on the parent chain. @default Derived from `zoneId` */
  portalAddress?: Address | undefined
  /** Encrypted recipient for the returned tokens. */
  recipient: Address
  /** Public recipient if the encrypted return fails. */
  recoveryRecipient: Address
  /** Optional memo encrypted with the returned Zone deposit. */
  returnMemo?: Hex.Hex | undefined
  /** Vault address. */
  vault: Address
  /** Optional memo attached to the Zone withdrawal. */
  withdrawalMemo?: Hex.Hex | undefined
  /** Source Zone receiving the output. */
  zoneId: number
}

type PreparedZoneRequest = {
  /** Correlation id for the matching wait action. */
  actionId: Hex.Hex
  /** Withdrawal amount, passed through to the Zone action. */
  amount: bigint
  /** Gas reserved for the parent-chain callback. */
  callbackGas: bigint
  /** Parent chain containing the gateway. */
  chainId: number
  /** Encoded gateway callback. */
  data: Hex.Hex
  /** Public recipient if the parent-chain callback fails. */
  fallbackRecipient: Address
  /** Parent-chain block before the withdrawal is submitted. */
  fromBlock: bigint
  /** Optional memo attached to the Zone withdrawal. */
  memo?: Hex.Hex | undefined
  /** Zone gateway receiving the withdrawal. */
  to: Address
  /** Token withdrawn from the Zone. */
  token: Address
  /** Zone containing the withdrawn tokens. */
  zoneId: number
}

const zoneGatewayCallbackGas = 10_000_000n

function resolveMinimumShareAmount(parameters: MinimumShareAmountParameters) {
  if (parameters.shareAmountMin !== undefined)
    return EarnShares.minimumOutput(parameters.shareAmountMin, 0)
  return EarnShares.minimumOutput(
    parameters.shareAmount,
    parameters.slippageBps,
  )
}

async function assertPreparedZoneRequestChain(
  client: Client<Transport, Chain | undefined>,
  parameters: PreparedZoneRequest,
) {
  const chain = client.chain
  if (!chain) throw new Error('`chain` is required.')
  if (chain.sourceId !== parameters.chainId)
    throw new Error(
      'Prepared Zone request parent chain ID does not match client chain.',
    )
  const { zoneId } = await zoneActions.getZoneInfo(client)
  if (zoneId !== parameters.zoneId)
    throw new Error(
      'Prepared Zone request Zone ID does not match client chain.',
    )
}

function pickReadParameters(parameters: Omit<ReadParameters, 'account'>) {
  const { blockOverrides, stateOverride } = parameters
  if (parameters.blockNumber !== undefined)
    return {
      blockNumber: parameters.blockNumber,
      blockOverrides,
      stateOverride,
    }
  return { blockOverrides, blockTag: parameters.blockTag, stateOverride }
}

async function getZoneGatewayConfig<chain extends Chain | undefined>(
  client: Client<Transport, chain>,
  parameters: Omit<ReadParameters, 'account'> & {
    flow: 0 | 1
    gateway: Address
    vault: Address
    zoneId: number
    zonePortal: Address
  },
) {
  const { flow, gateway, vault, zoneId, zonePortal, ...rest } = parameters
  const [
    vaultAsset,
    shareToken,
    gatewayVault,
    gatewayPrivateAsset,
    gatewayVaultAsset,
    gatewayShareToken,
    gatewayZoneId,
    supportsFlow,
  ] = await multicall(client, {
    ...rest,
    allowFailure: false,
    contracts: [
      {
        abi: Abis.earnVault,
        address: vault,
        functionName: 'asset',
      },
      {
        abi: Abis.earnVault,
        address: vault,
        functionName: 'earnShare',
      },
      {
        abi: Abis.earnRouter,
        address: gateway,
        functionName: 'earnVault',
      },
      {
        abi: Abis.earnRouter,
        address: gateway,
        functionName: 'privateAsset',
      },
      {
        abi: Abis.earnRouter,
        address: gateway,
        functionName: 'vaultAsset',
      },
      {
        abi: Abis.earnRouter,
        address: gateway,
        functionName: 'earnShare',
      },
      {
        abi: Abis.earnRouter,
        address: gateway,
        functionName: 'allowedZoneId',
      },
      {
        abi: Abis.earnRouter,
        address: gateway,
        args: [flow],
        functionName: 'supportsFlow',
      },
    ],
    deployless: true,
  })
  if (!supportsFlow) throw new Error('Zone gateway flow is not supported.')
  if (
    !isAddressEqual(gatewayVault, vault) ||
    !isAddressEqual(gatewayVaultAsset, vaultAsset) ||
    !isAddressEqual(gatewayShareToken, shareToken) ||
    gatewayZoneId !== zoneId
  )
    throw new Error('Zone gateway immutable configuration does not match.')
  return {
    privateAsset: gatewayPrivateAsset,
    shareToken,
    vault,
    vaultAsset,
    zoneId,
    zonePortal,
  }
}

// ERC-165 ids of the optional engine capability interfaces (XOR of each
// interface's function selectors).
const interfaceIds = {
  /** `IEarnEngineAsyncRedeem`. */
  asyncRedeem: '0xa1a6a1d7',
  /** `IEarnEngineExactWithdraw`. */
  exactWithdraw: '0x0adfb0b9',
  /** `IEarnEngineInKindDeposit`. */
  inKindDeposit: '0xce4790a9',
  /** `IEarnEngineRedeem`. */
  syncRedeem: '0x94a2d467',
} as const

/** Trims the decoded `FeeConfig` to its active fixed-fee count. */
function toFeeConfig(
  config: ReadContractReturnType<typeof Abis.earnFees, 'feeConfig'>,
): FeeConfig {
  return {
    excess: config.excess,
    fixedFees: config.fixedFees.slice(0, config.fixedFeeCount),
  }
}

/** Maps decoded fee fields to the action result. */
function toFeePreview(
  preview: ReadContractReturnType<typeof Abis.earnFees, 'previewAccruedFees'>,
): FeePreview {
  const {
    allocationCount,
    allocations,
    postFeeValuePerEarnShare,
    preFeeValuePerEarnShare,
    targetValuePerEarnShare,
    totalFeeEarnShares,
    ...rest
  } = preview
  return {
    ...rest,
    allocations: allocations
      .slice(0, allocationCount)
      .map(({ feeEarnShares, ...allocation }) => ({
        ...allocation,
        feeShares: feeEarnShares,
      })),
    postFeeValuePerShare: postFeeValuePerEarnShare,
    preFeeValuePerShare: preFeeValuePerEarnShare,
    targetValuePerShare: targetValuePerEarnShare,
    totalFeeShares: totalFeeEarnShares,
  }
}

/** Resolves `deposit` parameters into the adapter call args. @internal */
async function toDepositArgs(
  client: Client<Transport, Chain | undefined, Account | undefined>,
  parameters: deposit.Parameters,
): Promise<deposit.call.Args> {
  const { vault } = parameters
  const assetAmount = await toBaseUnitsLive(client, {
    amount: parameters.assetAmount,
    token: 'asset',
    vault,
  })
  const args = {
    assetAmount,
    recipient: resolveRecipient(client, parameters),
    vault,
  }
  if (parameters.shareAmountMin !== undefined)
    return { ...args, shareAmountMin: parameters.shareAmountMin }
  return {
    ...args,
    shareAmount: parameters.shareAmount,
    slippageBps: parameters.slippageBps,
  }
}

/** Resolves `depositShares` parameters into the adapter call args. @internal */
function toDepositSharesArgs(
  client: Client<Transport, Chain | undefined, Account | undefined>,
  parameters: depositShares.Parameters,
): depositShares.call.Args {
  const { vault, venueShareAmount } = parameters
  const args = {
    recipient: resolveRecipient(client, parameters),
    vault,
    venueShareAmount,
  }
  if (parameters.earnShareAmountMin !== undefined)
    return { ...args, earnShareAmountMin: parameters.earnShareAmountMin }
  return {
    ...args,
    earnShareAmount: parameters.earnShareAmount,
    slippageBps: parameters.slippageBps,
  }
}

/** Resolves `redeem` parameters into the adapter call args. @internal */
async function toRedeemArgs(
  client: Client<Transport, Chain | undefined, Account | undefined>,
  parameters: redeem.Parameters,
): Promise<redeem.call.Args> {
  const { vault } = parameters
  const shareAmount = await toBaseUnitsLive(client, {
    amount: parameters.shareAmount,
    token: 'shareToken',
    vault,
  })
  const args = {
    recipient: resolveRecipient(client, parameters),
    shareAmount,
    vault,
  }
  if (parameters.assetAmountMin !== undefined)
    return { ...args, assetAmountMin: parameters.assetAmountMin }
  const assetAmount = await (async () => {
    if (parameters.assetAmount !== undefined) return parameters.assetAmount
    return getRedeemQuote(client, { shareAmount, vault })
  })()
  return {
    ...args,
    assetAmount,
    slippageBps: parameters.slippageBps,
  }
}

/** Resolves `withdrawExact` parameters into the adapter call args. @internal */
async function toWithdrawExactArgs(
  client: Client<Transport, Chain | undefined, Account | undefined>,
  parameters: withdrawExact.Parameters,
): Promise<withdrawExact.call.Args> {
  const { vault } = parameters
  const assetAmount = await toBaseUnitsLive(client, {
    amount: parameters.assetAmount,
    token: 'asset',
    vault,
  })
  const args = {
    assetAmount,
    recipient: resolveRecipient(client, parameters),
    vault,
  }
  if (parameters.shareAmountMax !== undefined)
    return { ...args, shareAmountMax: parameters.shareAmountMax }
  const shareAmount = await (async () => {
    if (parameters.shareAmount !== undefined) return parameters.shareAmount
    return getWithdrawQuote(client, { assetAmount, vault })
  })()
  return {
    ...args,
    shareAmount,
    slippageBps: parameters.slippageBps,
  }
}

/** Validates that a prepared allocation is internally consistent. @internal */
function validateNestedAllocation(allocation: NestedAllocation) {
  if (allocation.assetAmount <= 0n)
    throw new Error('Nested asset amount must be greater than zero.')
  if (
    allocation.innerAssetAmount < 0n ||
    allocation.outerAssetAmount < 0n ||
    allocation.innerAssetAmount + allocation.outerAssetAmount !==
      allocation.assetAmount
  )
    throw new Error(
      'NestedEarnVaults allocation does not sum to the requested assets.',
    )
}

/** Rejects a composition whose roles resolve to one vault. @internal */
function validateNestedVaults(nested: NestedEarnVaults) {
  if (isAddressEqual(nested.innerVault, nested.outerVault))
    throw new Error('Inner and outer vaults must be different.')
}

/** Verifies that the outer vault's engine wraps the supplied inner vault. @internal */
async function validateNestedBinding(
  client: Client<Transport, Chain | undefined, Account | undefined>,
  nested: NestedEarnVaults,
) {
  validateNestedVaults(nested)
  const engine = await readContract(client, {
    abi: Abis.earnVault,
    address: nested.outerVault,
    functionName: 'engine',
  })
  const wrappedInnerVault = await readContract(client, {
    abi: Abis.earnVaultEngine,
    address: engine,
    functionName: 'baseVault',
  })
  if (!isAddressEqual(nested.innerVault, wrappedInnerVault))
    throw new Error('Outer vault does not wrap the supplied inner vault.')
}

/** Resolves and validates the common asset for one nested composition. @internal */
async function getNestedAsset(
  client: Client<Transport, Chain | undefined, Account | undefined>,
  nested: NestedEarnVaults,
) {
  const [innerAsset, outerAsset] = await Promise.all([
    readContract(client, {
      abi: Abis.earnVault,
      address: nested.innerVault,
      functionName: 'asset',
    }),
    readContract(client, {
      abi: Abis.earnVault,
      address: nested.outerVault,
      functionName: 'asset',
    }),
    validateNestedBinding(client, nested),
  ])
  if (!isAddressEqual(innerAsset, outerAsset))
    throw new Error('Inner and outer vault assets do not match.')
  return innerAsset
}

/** Requires a positive bound exactly when a nested leg is nonempty. @internal */
function validateNestedLeg(
  inputAmount: bigint,
  outputMinimum: bigint,
  label: string,
) {
  if (inputAmount < 0n || outputMinimum < 0n)
    throw new Error(`${label} amounts cannot be negative.`)
  if ((inputAmount === 0n) !== (outputMinimum === 0n))
    throw new Error(
      `${label} output minimum must be zero exactly when its input is zero.`,
    )
}

/** Resolves independent inner and outer redemption floors. @internal */
function nestedRedeemMinimums(args: redeemNested.Args) {
  if (args.innerAssetAmountMin !== undefined)
    return {
      innerAssetAmountMin: args.innerAssetAmountMin,
      outerAssetAmountMin: args.outerAssetAmountMin,
    }
  return {
    innerAssetAmountMin:
      args.innerAssetAmount === 0n
        ? 0n
        : EarnShares.minimumOutput(args.innerAssetAmount, args.slippageBps),
    outerAssetAmountMin:
      args.outerAssetAmount === 0n
        ? 0n
        : EarnShares.minimumOutput(args.outerAssetAmount, args.slippageBps),
  }
}

/** Raises a quoted input by basis points with ceiling rounding. @internal */
function maximumInput(shareAmount: bigint, slippageBps: number): bigint {
  if (shareAmount <= 0n)
    throw new EarnShares.InvalidExpectedOutputError({
      expectedAmount: shareAmount,
    })
  if (
    !Number.isInteger(slippageBps) ||
    slippageBps < 0 ||
    slippageBps >= EarnShares.basisPointScale
  )
    throw new EarnShares.InvalidSlippageError({ slippageBps })
  const scale = BigInt(EarnShares.basisPointScale)
  const numerator = shareAmount * (scale + BigInt(slippageBps))
  // Adding the denominator minus one converts floor division to ceiling.
  return (numerator + scale - 1n) / scale
}

/**
 * Converts an amount to base units, resolving missing decimals with live
 * reads of the vault's asset or share token. Earn share tokens are not
 * genesis-declared, so nothing is cached. @internal
 */
async function toBaseUnitsLive(
  client: Client<Transport, Chain | undefined>,
  options: {
    amount: internal_Token.AmountInput
    token: 'asset' | 'shareToken'
    vault: Address
  },
): Promise<bigint> {
  const { amount, token, vault } = options
  if (typeof amount === 'bigint') return amount
  if (amount.decimals !== undefined)
    return internal_Token.toBaseUnits(amount, amount.decimals)
  const address = await readContract(client, {
    abi: Abis.earnVault,
    address: vault,
    functionName: token === 'asset' ? 'asset' : 'earnShare',
  })
  const { decimals } = await resolveTokenWithDecimals(client, {
    token: address,
  })
  return internal_Token.toBaseUnits(amount, decimals)
}

/** Defaults a write's `recipient` to the sending account's address. @internal */
function resolveRecipient(
  client: Client<Transport, Chain | undefined, Account | undefined>,
  parameters: {
    account?: Account | Address | null | undefined
    recipient?: Address | undefined
  },
): Address {
  if (parameters.recipient) return parameters.recipient
  const account = parameters.account ?? client.account
  if (!account) throw new AccountNotFoundError()
  return parseAccount(account).address
}
