#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod kyc_contract {
    use ink::storage::Mapping;
    use scale::{Decode, Encode};
    use ink::prelude::vec::Vec;

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
    #[allow(clippy::cast_possible_truncation)]
    pub enum Status {
        Pending,
        Verified,
        Rejected,
    }

    #[derive(Debug, PartialEq, Eq, Encode, Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
    pub struct User {
        user_id: AccountId,
        name: Vec<u8>,
        address: Vec<u8>,
        dob: Vec<u8>,
        status: Status,
    }

    #[ink(storage)]
    pub struct KycContract {
        users: Mapping<AccountId, User>,
        kyc_status: Mapping<AccountId, Status>,
        blacklists: Mapping<AccountId, bool>,
        admin: AccountId,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo, ink::storage::traits::StorageLayout))]
    #[allow(clippy::cast_possible_truncation)]
    pub enum KycError {
        AlreadyRegistered,
        NotAuthorized,
        UserNotFound,
        VerificationFailed,
        Blacklisted,
    }

    impl KycContract {
        #[ink(constructor)]
        pub fn new(admin: AccountId) -> Self {
            Self {
                users: Mapping::default(),
                kyc_status: Mapping::default(),
                blacklists: Mapping::default(),
                admin,
            }
        }

        #[ink(message)]
        pub fn register_user(
            &mut self,
            name: Vec<u8>,
            address: Vec<u8>,
            dob: Vec<u8>,
        ) -> Result<(), KycError> {
            let caller = self.env().caller();

            if self.users.contains(&caller) {
                return Err(KycError::AlreadyRegistered);
            }

            let new_user = User {
                user_id: caller,
                name,
                address,
                dob,
                status: Status::Pending,
            };

            self.users.insert(&caller, &new_user);
            self.kyc_status.insert(&caller, &Status::Pending);

            Ok(())
        }

        #[ink(message)]
        pub fn verify_user(&mut self, user: AccountId) -> Result<(), KycError> {
            if self.env().caller() != self.admin {
                return Err(KycError::NotAuthorized);
            }

            if !self.users.contains(&user) {
                return Err(KycError::UserNotFound);
            }

            self.kyc_status.insert(&user, &Status::Verified);
            Ok(())
        }

        #[ink(message)]
        pub fn reject_user(&mut self, user: AccountId) -> Result<(), KycError> {
            if self.env().caller() != self.admin {
                return Err(KycError::NotAuthorized);
            }

            if !self.users.contains(&user) {
                return Err(KycError::UserNotFound);
            }

            self.kyc_status.insert(&user, &Status::Rejected);
            Ok(())
        }

        #[ink(message)]
        pub fn blacklist_user(&mut self, user: AccountId) -> Result<(), KycError> {
            if self.env().caller() != self.admin {
                return Err(KycError::NotAuthorized);
            }

            self.blacklists.insert(&user, &true);
            Ok(())
        }

        #[ink(message)]
        pub fn is_blacklisted(&self, user: AccountId) -> bool {
            self.blacklists.get(&user).unwrap_or(false)
        }

        #[ink(message)]
        pub fn get_user_status(&self, user: AccountId) -> Option<Status> {
            self.kyc_status.get(&user)
        }
    }
}


