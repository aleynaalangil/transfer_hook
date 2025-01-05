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
use std::cell::RefMut;

declare_id!("FTYJzS4zX9puYkmGE23zgtSkghLcjHeF6dYVoUabxpPk");

#[program]
pub mod transfer_hook {
    use super::*;

    #[interface(spl_transfer_hook_interface::initialize_extra_account_meta_list)]
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        let extra_account_metas = InitializeExtraAccountMetaList::extra_account_metas()?;
        ExtraAccountMetaList::init::<ExecuteInstruction>(
            &mut ctx.accounts.extra_account_meta_list.try_borrow_mut_data()?,
            &extra_account_metas,
        )?;
        Ok(())
    }

    #[interface(spl_transfer_hook_interface::execute)]
    pub fn transfer_hook(ctx: Context<TransferHook>, _amount: u64) -> Result<()> {
        check_is_transferring(&ctx)?;
        let destination_token_key = ctx.accounts.destination_token.key();
        let owner_wallet_key = ctx.accounts.owner.key();
        // Optionally do a CPI fetch to see if either "destination_token_key" or "owner_wallet_key"
        // has a "ShareholderWhitelist" account. For brevity, we skip that step here.
        // If no valid user found => revert.
        msg!(
            "transfer_hook finished, destination_token_key: {}, owner_wallet_key: {}",
            destination_token_key,
            owner_wallet_key
        );
        Ok(())
    }

    pub fn add_shareholder(
        ctx: Context<AddShareholder>,
        wallet: Pubkey,
        token_account: Pubkey,
    ) -> Result<()> {
        let s = &mut ctx.accounts.new_shareholder_whitelist;
        s.authority = ctx.accounts.authority.key();
        s.wallet = wallet;
        s.token_account = token_account;
        // s.bump = *ctx.bumps.get("new_shareholder_whitelist").unwrap();
        Ok(())
    }

    pub fn remove_shareholder(ctx: Context<RemoveShareholder>) -> Result<()> {
        msg!(
            "Removing user with wallet = {} and closing their ShareholderWhitelist PDA",
            ctx.accounts.shareholder_whitelist.wallet
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

#[error_code]
pub enum TransferError {
    #[msg("Not currently transferring")]
    IsNotCurrentlyTransferring,
}

#[derive(Accounts)]
pub struct InitializeExtraAccountMetaList<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK:
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
}

impl<'info> InitializeExtraAccountMetaList<'info> {
    pub fn extra_account_metas() -> Result<Vec<ExtraAccountMeta>> {
        Ok(vec![ExtraAccountMeta::new_with_seeds(
            &[Seed::Literal {
                bytes: "white_list".as_bytes().to_vec(),
            }],
            false,
            true,
        )?])
    }
}

#[derive(Accounts)]
pub struct TransferHook<'info> {
    #[account(token::mint = mint, token::authority = owner)]
    pub source_token: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    #[account(token::mint = mint)]
    pub destination_token: InterfaceAccount<'info, TokenAccount>,
    /// CHECK:
    pub owner: UncheckedAccount<'info>,
    /// CHECK:
    #[account(seeds = [b"extra-account-metas", mint.key().as_ref()], bump)]
    pub extra_account_meta_list: UncheckedAccount<'info>,
}

#[account]
pub struct ShareholderWhitelist {
    pub authority: Pubkey,
    pub wallet: Pubkey,
    pub token_account: Pubkey,
    pub bump: u8,
}

impl ShareholderWhitelist {
    pub const SIZE: usize = 32 + 32 + 32 + 1;
}

#[derive(Accounts)]
#[instruction(wallet: Pubkey, token_account: Pubkey)]
pub struct AddShareholder<'info> {
    #[account(
        init,
        payer = authority,
        seeds = [b"whitelist", wallet.as_ref()],
        bump,
        space = 8 + ShareholderWhitelist::SIZE
    )]
    pub new_shareholder_whitelist: Account<'info, ShareholderWhitelist>,

    #[account(mut)]
    pub authority: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct RemoveShareholder<'info> {
    #[account(
        mut,
        has_one = authority,
        close = authority
    )]
    pub shareholder_whitelist: Account<'info, ShareholderWhitelist>,
    #[account(mut)]
    pub authority: Signer<'info>,
}
