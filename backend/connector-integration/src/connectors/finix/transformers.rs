use crate::types::ResponseRouterData;
use common_enums::{AttemptStatus, RefundStatus};
use common_utils::{consts, pii::Email, types::MinorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, PSync, PaymentMethodToken, RSync, Refund, Void},
    connector_types::{
        ConnectorCustomerData, ConnectorCustomerResponse, PaymentFlowData,
        PaymentMethodTokenizationData, PaymentVoidData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, PaymentsSyncData, RefundFlowData, RefundSyncData, RefundsData,
        RefundsResponseData, ResponseId,
    },
    errors,
    payment_method_data::{BankDebitData, PaymentMethodData},
    router_data::ConnectorSpecificAuth,
    router_data_v2::RouterDataV2,
};
use hyperswitch_masking::{ExposeInterface, PeekInterface, Secret};
use serde::{Deserialize, Serialize};

use super::FinixRouterData;

// Empty request structures for GET requests that don't send request bodies
#[derive(Debug, Serialize, Default)]
pub struct FinixPSyncRequest {}

#[derive(Debug, Serialize, Default)]
pub struct FinixVoidRequest {}

#[derive(Debug, Serialize, Default)]
pub struct FinixRSyncRequest {}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    > for FinixPSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: FinixRouterData<
            RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for FinixVoidRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: FinixRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    > for FinixRSyncRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: FinixRouterData<
            RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self::default())
    }
}

// ===== AUTH TYPE =====
#[derive(Debug, Clone)]
pub struct FinixAuthType {
    pub api_key: Secret<String>,
    pub api_secret: Secret<String>,
    pub merchant_id: Secret<String>,
    pub identity_id: Secret<String>,
}

impl TryFrom<&ConnectorSpecificAuth> for FinixAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(auth_type: &ConnectorSpecificAuth) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificAuth::Finix {
                api_key,
                api_secret,
                merchant_id,
                identity_id,
            } => Ok(Self {
                api_key: api_key.to_owned(),
                api_secret: api_secret.to_owned(),
                merchant_id: merchant_id.to_owned(),
                identity_id: identity_id.to_owned(),
            }),
            _ => Err(error_stack::report!(
                errors::ConnectorError::FailedToObtainAuthType
            )),
        }
    }
}

// ===== ERROR RESPONSE =====
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinixErrorResponse {
    pub total: Option<i64>,
    pub _embedded: Option<FinixErrorEmbedded>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinixErrorEmbedded {
    pub errors: Vec<FinixErrorItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinixErrorItem {
    pub code: Option<String>,
    pub message: String,
    pub field: Option<String>,
}

impl FinixErrorResponse {
    pub fn get_error_message(&self) -> String {
        self._embedded
            .as_ref()
            .and_then(|e| e.errors.first())
            .map(|e| e.message.clone())
            .unwrap_or_else(|| consts::NO_ERROR_MESSAGE.to_string())
    }

    pub fn get_error_code(&self) -> Option<String> {
        self._embedded
            .as_ref()
            .and_then(|e| e.errors.first())
            .and_then(|e| e.code.clone())
    }
}

// ===== PAYMENT INSTRUMENT (TOKENIZATION) REQUEST =====
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum FinixPaymentInstrumentRequest {
    #[serde(rename = "BANK_ACCOUNT")]
    BankAccount(FinixBankAccountData),
}

#[derive(Debug, Serialize)]
pub struct FinixBankAccountData {
    pub account_number: Secret<String>,
    pub bank_code: Secret<String>,
    pub name: Secret<String>,
    pub account_type: FinixAccountType,
    pub company_name: Option<Secret<String>>,
    pub identity: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinixAccountType {
    Checking,
    Savings,
}

impl From<common_enums::BankType> for FinixAccountType {
    fn from(bank_type: common_enums::BankType) -> Self {
        match bank_type {
            common_enums::BankType::Savings => FinixAccountType::Savings,
            _ => FinixAccountType::Checking,
        }
    }
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                domain_types::connector_types::PaymentMethodTokenResponse,
            >,
            T,
        >,
    > for FinixPaymentInstrumentRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FinixRouterData<
            RouterDataV2<
                PaymentMethodToken,
                PaymentFlowData,
                PaymentMethodTokenizationData<T>,
                domain_types::connector_types::PaymentMethodTokenResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let identity_id = item
            .router_data
            .resource_common_data
            .connector_customer
            .clone()
            .ok_or(errors::ConnectorError::MissingRequiredField {
                field_name: "connector_customer_id (identity_id)",
            })?;

        match &item.router_data.request.payment_method_data {
            PaymentMethodData::BankDebit(BankDebitData::AchBankDebit {
                account_number,
                routing_number,
                bank_account_holder_name,
                bank_holder_type,
                bank_type,
                ..
            }) => {
                let name = bank_account_holder_name.clone().ok_or(
                    errors::ConnectorError::MissingRequiredField {
                        field_name: "bank_account_holder_name",
                    },
                )?;

                let bank_type = bank_type.ok_or(errors::ConnectorError::MissingRequiredField {
                    field_name: "bank_type",
                })?;

                let company_name = if matches!(
                    bank_holder_type,
                    Some(common_enums::BankHolderType::Business)
                ) {
                    Some(name.clone())
                } else {
                    None
                };

                Ok(Self::BankAccount(FinixBankAccountData {
                    account_number: account_number.clone(),
                    bank_code: routing_number.clone(),
                    name,
                    account_type: FinixAccountType::from(bank_type),
                    company_name,
                    identity: identity_id,
                }))
            }
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only ACH Bank Debit is supported for Finix".to_string(),
            ))?,
        }
    }
}

// ===== PAYMENT INSTRUMENT RESPONSE =====
#[derive(Debug, Deserialize, Serialize)]
pub struct FinixPaymentInstrumentResponse {
    pub id: String,
}

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<FinixPaymentInstrumentResponse, Self>>
    for RouterDataV2<
        PaymentMethodToken,
        PaymentFlowData,
        PaymentMethodTokenizationData<T>,
        domain_types::connector_types::PaymentMethodTokenResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixPaymentInstrumentResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(domain_types::connector_types::PaymentMethodTokenResponse {
                token: item.response.id,
            }),
            ..item.router_data
        })
    }
}

// ===== AUTHORIZE (TRANSFER) REQUEST =====
#[derive(Debug, Serialize)]
pub struct FinixTransferRequest {
    pub amount: MinorUnit,
    pub currency: String,
    pub merchant: String,
    pub source: String,
    pub tags: Option<FinixTags>,
}

#[derive(Debug, Serialize)]
pub struct FinixTags {
    pub order_number: String,
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for FinixTransferRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FinixRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let auth = FinixAuthType::try_from(&item.router_data.connector_auth_type)?;

        let source = if let Ok(pm_token) = item
            .router_data
            .resource_common_data
            .get_payment_method_token()
        {
            match pm_token {
                domain_types::router_data::PaymentMethodToken::Token(token) => token.expose(),
            }
        } else {
            return Err(errors::ConnectorError::MissingRequiredField {
                field_name: "payment_method_token (from PaymentMethodToken flow)",
            })?;
        };

        Ok(Self {
            amount: item.router_data.request.minor_amount,
            currency: item.router_data.request.currency.to_string(),
            merchant: auth.merchant_id.expose(),
            source,
            tags: Some(FinixTags {
                order_number: item
                    .router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            }),
        })
    }
}

// ===== TRANSFER RESPONSE =====
#[derive(Debug, Deserialize, Serialize)]
pub struct FinixTransferResponse {
    pub id: String,
    pub amount: MinorUnit,
    pub currency: String,
    pub state: FinixTransferState,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FinixTransferState {
    Pending,
    Succeeded,
    Failed,
    Canceled,
}

impl From<FinixTransferState> for AttemptStatus {
    fn from(state: FinixTransferState) -> Self {
        match state {
            FinixTransferState::Pending => AttemptStatus::Pending,
            FinixTransferState::Succeeded => AttemptStatus::Charged,
            FinixTransferState::Failed => AttemptStatus::Failure,
            FinixTransferState::Canceled => AttemptStatus::Voided,
        }
    }
}

pub type FinixAuthorizeResponse = FinixTransferResponse;
pub type FinixPSyncResponse = FinixTransferResponse;

impl<T: domain_types::payment_method_data::PaymentMethodDataTypes>
    TryFrom<ResponseRouterData<FinixTransferResponse, Self>>
    for RouterDataV2<Authorize, PaymentFlowData, PaymentsAuthorizeData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixTransferResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = item.response.state.clone().into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<FinixTransferResponse, Self>>
    for RouterDataV2<PSync, PaymentFlowData, PaymentsSyncData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixTransferResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = item.response.state.clone().into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ===== CAPTURE REQUEST =====
// Finix does not support separate capture - transfers are automatically captured
// This is a placeholder for API compatibility
#[derive(Debug, Serialize, Default)]
pub struct FinixCaptureRequest {}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for FinixCaptureRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: FinixRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        // Finix transfers are automatically captured
        Ok(Self::default())
    }
}

// ===== CAPTURE RESPONSE =====
pub type FinixCaptureResponse = FinixTransferResponse;

impl TryFrom<ResponseRouterData<FinixTransferResponse, Self>>
    for RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixTransferResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = item.response.state.clone().into();

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ===== VOID REQUEST =====
// Finix uses PUT /transfers/{id} with {"action": "CANCEL"} to void
#[derive(Debug, Serialize)]
pub struct FinixVoidTransferRequest {
    pub action: String,
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    > for FinixVoidTransferRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        _item: FinixRouterData<
            RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            action: "CANCEL".to_string(),
        })
    }
}

pub type FinixVoidResponse = FinixTransferResponse;

impl TryFrom<ResponseRouterData<FinixTransferResponse, Self>>
    for RouterDataV2<Void, PaymentFlowData, PaymentVoidData, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixTransferResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let status = if matches!(item.response.state, FinixTransferState::Canceled) {
            AttemptStatus::Voided
        } else {
            AttemptStatus::VoidFailed
        };

        Ok(Self {
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id),
                redirection_data: None,
                mandate_reference: None,
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                status_code: item.http_code,
            }),
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            ..item.router_data
        })
    }
}

// ===== REFUND REQUEST =====
// Finix uses POST /transfers/{id}/reversals to refund
#[derive(Debug, Serialize)]
pub struct FinixRefundRequest {
    pub refund_amount: MinorUnit,
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    > for FinixRefundRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FinixRouterData<
            RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            refund_amount: item.router_data.request.minor_refund_amount,
        })
    }
}

// ===== REFUND RESPONSE =====
#[derive(Debug, Deserialize, Serialize)]
pub struct FinixReversalResponse {
    pub id: String,
    pub amount: MinorUnit,
    pub state: FinixTransferState,
}

pub type FinixRefundResponse = FinixReversalResponse;
pub type FinixRSyncResponse = FinixReversalResponse;

impl TryFrom<ResponseRouterData<FinixReversalResponse, Self>>
    for RouterDataV2<Refund, RefundFlowData, RefundsData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixReversalResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = match item.response.state {
            FinixTransferState::Succeeded => RefundStatus::Success,
            FinixTransferState::Failed => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

impl TryFrom<ResponseRouterData<FinixReversalResponse, Self>>
    for RouterDataV2<RSync, RefundFlowData, RefundSyncData, RefundsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixReversalResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let refund_status = match item.response.state {
            FinixTransferState::Succeeded => RefundStatus::Success,
            FinixTransferState::Failed => RefundStatus::Failure,
            _ => RefundStatus::Pending,
        };

        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ===== CREATE CONNECTOR CUSTOMER (IDENTITY) REQUEST =====
// Finix requires an Identity to be created before tokenizing payment methods
#[derive(Debug, Serialize)]
pub struct FinixIdentityRequest {
    pub entity: FinixEntity,
}

#[derive(Debug, Serialize)]
pub struct FinixEntity {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Email>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub business_tax_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doing_business_as: Option<String>,
}

impl<
        T: domain_types::payment_method_data::PaymentMethodDataTypes
            + std::fmt::Debug
            + Sync
            + Send
            + 'static
            + Serialize,
    >
    TryFrom<
        FinixRouterData<
            RouterDataV2<
                domain_types::connector_flow::CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
            T,
        >,
    > for FinixIdentityRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: FinixRouterData<
            RouterDataV2<
                domain_types::connector_flow::CreateConnectorCustomer,
                PaymentFlowData,
                ConnectorCustomerData,
                ConnectorCustomerResponse,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let entity = FinixEntity {
            first_name: item
                .router_data
                .request
                .name
                .as_ref()
                .map(|n| n.peek().clone()),
            last_name: None,
            email: item
                .router_data
                .request
                .email
                .as_ref()
                .map(|e| e.peek().clone()),
            phone: None,
            business_name: None,
            business_type: None,
            business_phone: None,
            business_tax_id: None,
            doing_business_as: None,
        };

        Ok(Self { entity })
    }
}

// ===== CREATE CONNECTOR CUSTOMER (IDENTITY) RESPONSE =====
#[derive(Debug, Deserialize, Serialize)]
pub struct FinixIdentityResponse {
    pub id: String,
}

impl TryFrom<ResponseRouterData<FinixIdentityResponse, Self>>
    for RouterDataV2<
        domain_types::connector_flow::CreateConnectorCustomer,
        PaymentFlowData,
        ConnectorCustomerData,
        ConnectorCustomerResponse,
    >
{
    type Error = error_stack::Report<errors::ConnectorError>;

    fn try_from(
        item: ResponseRouterData<FinixIdentityResponse, Self>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(ConnectorCustomerResponse {
                connector_customer_id: item.response.id,
            }),
            ..item.router_data
        })
    }
}
