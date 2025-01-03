use std::cell::RefMut;

use anchor_lang::prelude::*;
use anchor_spl::{
    token_2022::spl_token_2022::{
        extension::{
            transfer_hook::TransferHookAccount, BaseStateWithExtensionsMut,
            PodStateWithExtensionsMut,
        },
        pod::PodAccount,
    },
    token_interface::{Mint, TokenAccount},
};
use spl_tlv_account_resolution::{
    account::ExtraAccountMeta, seeds::Seed, state::ExtraAccountMetaList,
};
use spl_transfer_hook_interface::instruction::ExecuteInstruction;

declare_id!("EGqyf8VoRxvyoy7Fxtowu6UAp83CZgNFuks6DsNHr17G");

#[error_code]
pub enum TransferError {
    #[msg("The token is not currently transferring")]
    IsNotCurrentlyTransferring,
    #[msg("Only the whitelist authority can modify the whitelist")]
    NotWhitelistAuthority,
    #[msg("This (token_account, wallet_account) pair is already whitelisted")]
    WalletAlreadyWhitelisted,
}

#[program]
pub mod transfer_hook {
    //whitelisting
    use super::*;

    #[interface(spl_transfer_hook_interface::initialize_extra_account_meta_list)]
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        // set authority field on white_list account as payer address
        ctx.accounts.white_list.authority = ctx.accounts.payer.key();

        let extra_account_metas = InitializeExtraAccountMetaList::extra_account_metas()?;

        // initialize ExtraAccountMetaList account with extra accounts
        ExtraAccountMetaList::init::<ExecuteInstruction>(
            &mut ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?,
            &extra_account_metas,
        )?;
        Ok(())
    }

    // #[interface(spl_transfer_hook_interface::execute)]
    // pub fn transfer_hook(ctx: Context<TransferHook>, _amount: u64) -> Result<()> {
    //     // Fail this instruction if it is not called from within a transfer hook
    //     check_is_transferring(&ctx)?;

    //     if !ctx
    //         .accounts
    //         .white_list
    //         .white_list
    //         .contains(&ctx.accounts.destination_token.key())
    //     {
    //         panic!("Account not in white list!");
    //     }

    //     msg!("Account in white list, all good!");

    //     Ok(())
    // }
    #[interface(spl_transfer_hook_interface::execute)]
    pub fn transfer_hook(ctx: Context<TransferHook>, _amount: u64) -> Result<()> {
        // Fail this instruction if it is not called from within a transfer hook
        check_is_transferring(&ctx)?;

        let destination_token_key = ctx.accounts.destination_token.key();
        let owner_wallet_key = ctx.accounts.owner.key();

        // We check if (destination token) or (owner wallet) is whitelisted
        let is_whitelisted = ctx
            .accounts
            .white_list
            .white_list
            .iter()
            .any(|entry| {
                // If either the token account or the controlling wallet is in the list
                entry.token_account == destination_token_key
                 || entry.wallet_account == owner_wallet_key
            });

        if !is_whitelisted {
            panic!("Neither the token account nor the wallet is in the whitelist!");
        }

        msg!("Destination is whitelisted (token or wallet), all good!");
        Ok(())
    }
    
    pub fn add_to_whitelist(
        ctx: Context<AddToWhiteList>,
        wallet_account: Pubkey,   // new param for the controlling wallet
    ) -> Result<()> {
        // Ensure only the authority can add
        if ctx.accounts.white_list.authority != ctx.accounts.signer.key() {
            return err!(TransferError::NotWhitelistAuthority);
        }

        let token_account_key = ctx.accounts.new_account.key();

        // Check if this (token_account, wallet_account) is already in the list
        let already_in_list = ctx.accounts.white_list.white_list.iter().any(|entry| {
            entry.token_account == token_account_key && entry.wallet_account == wallet_account
        });
        if already_in_list {
            return err!(TransferError::WalletAlreadyWhitelisted);
        }

        // If not present, push a new WhitelistEntry
        let entry = WhitelistEntry {
            token_account: token_account_key,
            wallet_account,
        };
        ctx.accounts.white_list.white_list.push(entry);

        msg!(
            "New account whitelisted! token={}, wallet={}",
            token_account_key,
            wallet_account
        );
        msg!(
            "White list length = {}",
            ctx.accounts.white_list.white_list.len()
        );

        Ok(())
    }
    // pub fn remove_from_whitelist(
    //     ctx: Context<RemoveFromWhiteList>,
    //     wallet_account: Pubkey,
    // ) -> Result<()> {
    //     if ctx.accounts.white_list.authority != ctx.accounts.signer.key() {
    //         panic!("Only the authority can remove from the white list!");
    //     }
    
    //     let token_account_key = ctx.accounts.account_to_remove.key();
    //     let wl = &mut ctx.accounts.white_list.white_list;
    
    //     // Retain everything that does NOT match both the token & wallet
    //     wl.retain(|entry| {
    //         !(entry.token_account == token_account_key
    //           && entry.wallet_account == wallet_account)
    //     });
    
    //     msg!("Removed token={}, wallet={} from whitelist (if present).", token_account_key, wallet_account);
    //     msg!("Whitelist length = {}", wl.len());
    //     Ok(())
    // }
    pub fn remove_from_whitelist(
        ctx: Context<RemoveFromWhiteList>,
        wallet_account: Pubkey, // controlling wallet
    ) -> Result<()> {
        // Ensure only the authority can remove
        if ctx.accounts.white_list.authority != ctx.accounts.signer.key() {
            return err!(TransferError::NotWhitelistAuthority);
        }

        let token_account_key = ctx.accounts.account_to_remove.key();
        let wl = &mut ctx.accounts.white_list.white_list;

        // Retain everything that does NOT match (token_account, wallet_account)
        let old_len = wl.len();
        wl.retain(|entry| {
            !(
                entry.token_account == token_account_key 
                && entry.wallet_account == wallet_account
            )
        });
        let new_len = wl.len();

        msg!("Removed token={}, wallet={} from whitelist (if present). Old len={}, new len={}",
            token_account_key, wallet_account, old_len, new_len
        );
        Ok(())
    }
    
}

fn check_is_transferring(ctx: &Context<TransferHook>) -> Result<()> {
    let source_token_info = ctx.accounts.source_token.to_account_info();
    let mut account_data_ref: RefMut<&mut [u8]> = source_token_info.try_borrow_mut_data()?;
    let mut account = PodStateWithExtensionsMut::<PodAccount>::unpack(*account_data_ref)?;
    let account_extension = account.get_extension_mut::<TransferHookAccount>()?;

    if !bool::from(account_extension.transferring) {
        return err!(TransferError::IsNotCurrentlyTransferring);
    }

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    #[account(mut)]
    payer: Signer<'info>,

    /// CHECK: ExtraAccountMetaList Account, must use these seeds
    #[account(
        init,
        seeds = [b"extra-account-metas", mint.key().as_ref()],
        bump,
        space = ExtraAccountMetaList::size_of(
            InitializeExtraAccountMetaList::extra_account_metas()?.len()
        )?,
        payer = payer
    )]
    pub extra_account_meta_list: AccountInfo<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub system_program: Program<'info, System>,
    #[account(init_if_needed, seeds = [b"white_list"], bump, payer = payer, space = 1024)]
    pub white_list: Account<'info, WhiteList>,
}

// Define extra account metas to store on extra_account_meta_list account
impl<'info> InitializeExtraAccountMetaList<'info> {
    pub fn extra_account_metas() -> Result<Vec<ExtraAccountMeta>> {
        Ok(vec![ExtraAccountMeta::new_with_seeds(
            &[Seed::Literal {
                bytes: "white_list".as_bytes().to_vec(),
            }],
            false, // is_signer
            true,  // is_writable
        )?])
    }
}

// Order of accounts matters for this struct.
// The first 4 accounts are the accounts required for token transfer (source, mint, destination, owner)
// Remaining accounts are the extra accounts required from the ExtraAccountMetaList account
// These accounts are provided via CPI to this program from the token2022 program
#[derive(Accounts)]
pub struct TransferHook<'info> {
    #[account(token::mint = mint, token::authority = owner)]
    pub source_token: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(token::mint = mint)]
    pub destination_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: source token account owner, can be SystemAccount or PDA owned by another program
    pub owner: UncheckedAccount<'info>,
    /// CHECK: ExtraAccountMetaList Account,
    #[account(seeds = [b"extra-account-metas", mint.key().as_ref()], bump)]
    pub extra_account_meta_list: UncheckedAccount<'info>,
    #[account(seeds = [b"white_list"], bump)]
    pub white_list: Account<'info, WhiteList>,
}

#[derive(Accounts)]
pub struct AddToWhiteList<'info> {
    /// CHECK: New account to add to white list
    #[account()]
    pub new_account: AccountInfo<'info>,
    #[account(
        mut,
        seeds = [b"white_list"],
        bump
    )]
    pub white_list: Account<'info, WhiteList>,
    #[account(mut)]
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct RemoveFromWhiteList<'info> {
    /// The token account you want to remove
    /// (and we might also need the wallet key as an arg too)
    /// /// CHECK: account_to_remove is a token account
    #[account()]
    pub account_to_remove: AccountInfo<'info>,

    #[account(mut)]
    pub white_list: Account<'info, WhiteList>,

    #[account(mut)]
    pub signer: Signer<'info>,
}


#[account]
pub struct WhiteList {
    pub authority: Pubkey,
    pub white_list: Vec<WhitelistEntry>,
}
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct WhitelistEntry {
    pub token_account: Pubkey,
    pub wallet_account: Pubkey,
}