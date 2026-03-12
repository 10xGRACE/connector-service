use common_utils::{ext_traits::OptionExt, request::Method, FloatMajorUnit, StringMajorUnit};
use domain_types::{
    connector_flow::{Authorize, Capture, RepeatPayment, SetupMandate},
    connector_types::{
        MandateReferenceId, PaymentFlowData, PaymentsAuthorizeData, PaymentsCaptureData,
        PaymentsResponseData, RefundFlowData, RefundsData, RefundsResponseData, RepeatPaymentData,
        ResponseId, SetupMandateRequestData,
    },
    errors::ConnectorError,
    payment_method_data::{
        BankDebitData, PaymentMethodData, PaymentMethodDataTypes, RawCardNumber, WalletData,
    },
    router_data::{ConnectorSpecificAuth, ErrorResponse},
    router_data_v2::RouterDataV2,
    router_response_types::RedirectForm,
};
use error_stack;
use error_stack::ResultExt;
use hyperswitch_masking::Secret;
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Debug;
use url::Url;

use super::RapydRouterData;
use crate::types::ResponseRouterData;

impl<F, T> TryFrom<ResponseRouterData<RapydPaymentsResponse, Self>>
    for RouterDataV2<F, PaymentFlowData, T, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RapydPaymentsResponse, Self>,
    ) -> Result<Self, Self::Error> {
        let (status, response) = match &item.response.data {
            Some(data) => {
                let attempt_status =
                    get_status(data.status.to_owned(), data.next_action.to_owned());
                match attempt_status {
                    common_enums::AttemptStatus::Failure => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: data
                                .failure_code
                                .to_owned()
                                .unwrap_or(item.response.status.error_code),
                            status_code: item.http_code,
                            message: item.response.status.status.unwrap_or_default(),
                            reason: data.failure_message.to_owned(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                    _ => {
                        let redirection_url = data
                            .redirect_url
                            .as_ref()
                            .filter(|redirect_str| !redirect_str.is_empty())
                            .map(|url| {
                                Url::parse(url)
                                    .change_context(ConnectorError::FailedToObtainIntegrationUrl)
                            })
                            .transpose()?;

                        let redirection_data =
                            redirection_url.map(|url| RedirectForm::from((url, Method::Get)));

                        (
                            attempt_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(data.id.to_owned()), //transaction_id is also the field but this id is used to initiate a refund
                                redirection_data: redirection_data.map(Box::new),
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: data
                                    .merchant_reference_id
                                    .to_owned(),
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                        )
                    }
                }
            }
            None => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: item.response.status.error_code,
                    status_code: item.http_code,
                    message: item.response.status.status.unwrap_or_default(),
                    reason: item.response.status.message,
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

#[derive(Debug, Serialize)]
pub struct EmptyRequest;

// RapydRouterData is now generated by the macro in rapyd.rs

#[derive(Debug, Serialize)]
pub struct RapydAuthType {
    pub(super) access_key: Secret<String>,
    pub(super) secret_key: Secret<String>,
}

impl TryFrom<&ConnectorSpecificAuth> for RapydAuthType {
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(auth_type: &ConnectorSpecificAuth) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorSpecificAuth::Rapyd {
                access_key,
                secret_key,
            } => Ok(Self {
                access_key: access_key.to_owned(),
                secret_key: secret_key.to_owned(),
            }),
            _ => Err(ConnectorError::FailedToObtainAuthType)?,
        }
    }
}

#[derive(Default, Debug, Serialize)]
pub struct RapydPaymentsRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    pub amount: StringMajorUnit,
    pub currency: common_enums::Currency,
    pub payment_method: PaymentMethod<T>,
    pub payment_method_options: Option<PaymentMethodOptions>,
    pub merchant_reference_id: Option<String>,
    pub capture: Option<bool>,
    pub description: Option<String>,
    pub complete_payment_url: Option<String>,
    pub error_payment_url: Option<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct PaymentMethodOptions {
    #[serde(rename = "3d_required")]
    pub three_ds: bool,
}

#[derive(Default, Debug, Serialize)]
pub struct PaymentMethod<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    #[serde(rename = "type")]
    pub pm_type: String,
    pub fields: Option<PaymentFields<T>>,
    pub address: Option<Address>,
    pub digital_wallet: Option<RapydWallet>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ach: Option<RapydAchDetails>,
}

#[derive(Debug, Serialize)]
pub struct RapydAchDetails {
    pub account_number: Secret<String>,
    pub routing_number: Secret<String>,
    pub account_type: String,
    pub account_holder_name: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct PaymentFields<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize> {
    pub number: RawCardNumber<T>,
    pub expiration_month: Secret<String>,
    pub expiration_year: Secret<String>,
    pub name: Secret<String>,
    pub cvv: Secret<String>,
}

#[derive(Default, Debug, Serialize)]
pub struct Address {
    name: Secret<String>,
    line_1: Secret<String>,
    line_2: Option<Secret<String>>,
    line_3: Option<Secret<String>>,
    city: Option<String>,
    state: Option<Secret<String>>,
    country: Option<String>,
    zip: Option<Secret<String>>,
    phone_number: Option<Secret<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RapydWallet {
    #[serde(rename = "type")]
    payment_type: String,
    #[serde(rename = "details")]
    token: Option<Secret<String>>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RapydRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RapydPaymentsRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<
            RouterDataV2<
                Authorize,
                PaymentFlowData,
                PaymentsAuthorizeData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let (capture, payment_method_options) =
            match item.router_data.resource_common_data.payment_method {
                common_enums::PaymentMethod::Card => {
                    let three_ds_enabled = matches!(
                        item.router_data.resource_common_data.auth_type,
                        common_enums::AuthenticationType::ThreeDs
                    );
                    let payment_method_options = PaymentMethodOptions {
                        three_ds: three_ds_enabled,
                    };
                    (
                        Some(matches!(
                            item.router_data.request.capture_method,
                            Some(common_enums::CaptureMethod::Automatic)
                                | Some(common_enums::CaptureMethod::SequentialAutomatic)
                                | None
                        )),
                        Some(payment_method_options),
                    )
                }
                _ => (None, None),
            };
        let payment_method = match item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ref ccard) => {
                Some(PaymentMethod {
                    pm_type: "in_amex_card".to_owned(), //[#369] Map payment method type based on country
                    fields: Some(PaymentFields {
                        number: ccard.card_number.to_owned(),
                        expiration_month: ccard.card_exp_month.to_owned(),
                        expiration_year: ccard.card_exp_year.to_owned(),
                        name: item
                            .router_data
                            .resource_common_data
                            .get_optional_billing_full_name()
                            .to_owned()
                            .unwrap_or(Secret::new("".to_string())),
                        cvv: ccard.card_cvc.to_owned(),
                    }),
                    address: None,
                    digital_wallet: None,
                    ach: None,
                })
            }
            PaymentMethodData::Wallet(ref wallet_data) => {
                let digital_wallet = match wallet_data {
                    WalletData::GooglePay(data) => Some(RapydWallet {
                        payment_type: "google_pay".to_string(),
                        token: Some(Secret::new(
                            data.tokenization_data
                                .get_encrypted_google_pay_token()
                                .change_context(ConnectorError::MissingRequiredField {
                                    field_name: "gpay wallet_token",
                                })?
                                .to_owned(),
                        )),
                    }),
                    WalletData::ApplePay(data) => {
                        let apple_pay_encrypted_data = data
                            .payment_data
                            .get_encrypted_apple_pay_payment_data_mandatory()
                            .change_context(ConnectorError::MissingRequiredField {
                                field_name: "Apple pay encrypted data",
                            })?;
                        Some(RapydWallet {
                            payment_type: "apple_pay".to_string(),
                            token: Some(Secret::new(apple_pay_encrypted_data.to_string())),
                        })
                    }
                    _ => None,
                };
                Some(PaymentMethod {
                    pm_type: "by_visa_card".to_string(), //[#369]
                    fields: None,
                    address: None,
                    digital_wallet,
                    ach: None,
                })
            }
            PaymentMethodData::BankDebit(BankDebitData::AchBankDebit {
                ref account_number,
                ref routing_number,
                ref bank_account_holder_name,
                bank_type,
                ..
            }) => {
                // Map bank_type to Rapyd ACH type
                let account_type = match bank_type {
                    Some(common_enums::BankType::Savings) => "savings".to_string(),
                    _ => "checking".to_string(),
                };

                // Get account holder name
                let account_holder_name = bank_account_holder_name
                    .clone()
                    .or_else(|| {
                        item.router_data
                            .resource_common_data
                            .get_optional_billing_full_name()
                    })
                    .unwrap_or(Secret::new("".to_string()));

                Some(PaymentMethod {
                    pm_type: "us_ach_bank".to_string(), // Rapyd ACH payment method type
                    fields: None,
                    address: None,
                    digital_wallet: None,
                    ach: Some(RapydAchDetails {
                        account_number: account_number.clone(),
                        routing_number: routing_number.clone(),
                        account_type,
                        account_holder_name,
                    }),
                })
            }
            _ => None,
        }
        .get_required_value("payment_method not implemented")
        .change_context(ConnectorError::NotImplemented("payment_method".to_owned()))?;
        let return_url = item.router_data.request.get_router_return_url()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;
        Ok(Self {
            amount,
            currency: item.router_data.request.currency,
            payment_method,
            capture,
            payment_method_options,
            merchant_reference_id: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            description: None,
            error_payment_url: Some(return_url.clone()),
            complete_payment_url: Some(return_url),
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum RapydPaymentStatus {
    #[serde(rename = "ACT")]
    Active,
    #[serde(rename = "CAN")]
    CanceledByClientOrBank,
    #[serde(rename = "CLO")]
    Closed,
    #[serde(rename = "ERR")]
    Error,
    #[serde(rename = "EXP")]
    Expired,
    #[serde(rename = "REV")]
    ReversedByRapyd,
    #[default]
    #[serde(rename = "NEW")]
    New,
}

fn get_status(status: RapydPaymentStatus, next_action: NextAction) -> common_enums::AttemptStatus {
    match (status, next_action) {
        (RapydPaymentStatus::Closed, _) => common_enums::AttemptStatus::Charged,
        (
            RapydPaymentStatus::Active,
            NextAction::ThreedsVerification | NextAction::PendingConfirmation,
        ) => common_enums::AttemptStatus::AuthenticationPending,
        (RapydPaymentStatus::Active, NextAction::PendingCapture | NextAction::NotApplicable) => {
            common_enums::AttemptStatus::Authorized
        }
        (
            RapydPaymentStatus::CanceledByClientOrBank
            | RapydPaymentStatus::Expired
            | RapydPaymentStatus::ReversedByRapyd,
            _,
        ) => common_enums::AttemptStatus::Voided,
        (RapydPaymentStatus::Error, _) => common_enums::AttemptStatus::Failure,
        (RapydPaymentStatus::New, _) => common_enums::AttemptStatus::Authorizing,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RapydPaymentsResponse {
    pub status: Status,
    pub data: Option<ResponseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Status {
    pub error_code: String,
    pub status: Option<String>,
    pub message: Option<String>,
    pub response_code: Option<String>,
    pub operation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NextAction {
    #[serde(rename = "3d_verification")]
    ThreedsVerification,
    #[serde(rename = "pending_capture")]
    PendingCapture,
    #[serde(rename = "not_applicable")]
    NotApplicable,
    #[serde(rename = "pending_confirmation")]
    PendingConfirmation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResponseData {
    pub id: String,
    pub amount: FloatMajorUnit,
    pub status: RapydPaymentStatus,
    pub next_action: NextAction,
    pub redirect_url: Option<String>,
    pub original_amount: Option<FloatMajorUnit>,
    pub is_partial: Option<bool>,
    pub currency_code: Option<common_enums::Currency>,
    pub country_code: Option<String>,
    pub captured: Option<bool>,
    pub transaction_id: String,
    pub merchant_reference_id: Option<String>,
    pub paid: Option<bool>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    // Payment method ID returned when save_payment_method=true (for SetupMandate flow)
    pub payment_method: Option<String>,
}

// Capture Request
#[derive(Debug, Serialize, Clone)]
pub struct CaptureRequest {
    amount: Option<StringMajorUnit>,
    receipt_email: Option<Secret<String>>,
    statement_descriptor: Option<String>,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RapydRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    > for CaptureRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<
            RouterDataV2<Capture, PaymentFlowData, PaymentsCaptureData, PaymentsResponseData>,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount_to_capture,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::AmountConversionFailed)?;
        Ok(Self {
            amount: Some(amount),
            receipt_email: None,
            statement_descriptor: None,
        })
    }
}

// Refund Request
#[derive(Default, Debug, Serialize)]
pub struct RapydRefundRequest {
    pub payment: String,
    pub amount: Option<StringMajorUnit>,
    pub currency: Option<common_enums::Currency>,
}

impl<F, T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<RapydRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>>
    for RapydRefundRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<RouterDataV2<F, RefundFlowData, RefundsData, RefundsResponseData>, T>,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_refund_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::AmountConversionFailed)?;
        Ok(Self {
            payment: item
                .router_data
                .request
                .connector_transaction_id
                .to_string(),
            amount: Some(amount),
            currency: Some(item.router_data.request.currency),
        })
    }
}

// Refund Response
#[allow(dead_code)]
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub enum RefundStatus {
    Completed,
    Error,
    Rejected,
    #[default]
    Pending,
}

impl From<RefundStatus> for common_enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Completed => Self::Success,
            RefundStatus::Error | RefundStatus::Rejected => Self::Failure,
            RefundStatus::Pending => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub status: Status,
    pub data: Option<RefundResponseData>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RefundResponseData {
    pub id: String,
    pub payment: String,
    pub amount: FloatMajorUnit,
    pub currency: common_enums::Currency,
    pub status: RefundStatus,
    pub created_at: Option<i64>,
    pub failure_reason: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<RefundResponse, Self>>
    for RouterDataV2<F, RefundFlowData, T, RefundsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(item: ResponseRouterData<RefundResponse, Self>) -> Result<Self, Self::Error> {
        let (connector_refund_id, refund_status) = match item.response.data {
            Some(data) => (data.id, common_enums::RefundStatus::from(data.status)),
            None => (
                item.response.status.error_code,
                common_enums::RefundStatus::Failure,
            ),
        };
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id,
                refund_status,
                status_code: item.http_code,
            }),
            ..item.router_data
        })
    }
}

// ============== SETUP MANDATE (MIT - Customer Initiated Transaction) ==============
// SetupMandate: First transaction to save payment method for future use
// Uses POST /v1/payments with save_payment_method=true and initiation_type="customer"

/// Response type for SetupMandate - reuses RapydPaymentsResponse
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RapydSetupMandateResponse(pub RapydPaymentsResponse);

#[derive(Default, Debug, Serialize)]
pub struct RapydSetupMandateRequest<
    T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize,
> {
    pub amount: StringMajorUnit,
    pub currency: common_enums::Currency,
    pub payment_method: PaymentMethod<T>,
    pub payment_method_options: Option<PaymentMethodOptions>,
    pub merchant_reference_id: Option<String>,
    pub capture: Option<bool>,
    pub description: Option<String>,
    pub complete_payment_url: Option<String>,
    pub error_payment_url: Option<String>,
    pub save_payment_method: bool,
    pub initiation_type: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RapydRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RapydSetupMandateRequest<T>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<
            RouterDataV2<
                SetupMandate,
                PaymentFlowData,
                SetupMandateRequestData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let payment_method = match item.router_data.request.payment_method_data {
            PaymentMethodData::Card(ref ccard) => Some(PaymentMethod {
                pm_type: "in_amex_card".to_owned(),
                fields: Some(PaymentFields {
                    number: ccard.card_number.to_owned(),
                    expiration_month: ccard.card_exp_month.to_owned(),
                    expiration_year: ccard.card_exp_year.to_owned(),
                    name: item
                        .router_data
                        .resource_common_data
                        .get_optional_billing_full_name()
                        .to_owned()
                        .unwrap_or(Secret::new("".to_string())),
                    cvv: ccard.card_cvc.to_owned(),
                }),
                address: None,
                digital_wallet: None,
                ach: None,
            }),
            _ => None,
        }
        .get_required_value("payment_method not implemented")
        .change_context(ConnectorError::NotImplemented("payment_method".to_owned()))?;

        let return_url = item.router_data.request.get_router_return_url()?;
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data
                    .request
                    .minor_amount
                    .unwrap_or(common_utils::types::MinorUnit::new(0)),
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        Ok(Self {
            amount,
            currency: item.router_data.request.currency,
            payment_method,
            capture: Some(true),
            payment_method_options: None,
            merchant_reference_id: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            description: Some("Setup mandate".to_string()),
            error_payment_url: Some(return_url.clone()),
            complete_payment_url: Some(return_url),
            save_payment_method: true,
            initiation_type: "customer".to_string(),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<RapydSetupMandateResponse, Self>>
    for RouterDataV2<
        SetupMandate,
        PaymentFlowData,
        SetupMandateRequestData<T>,
        PaymentsResponseData,
    >
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RapydSetupMandateResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Unwrap the inner RapydPaymentsResponse from the wrapper
        let inner_response = &item.response.0;
        let (status, response) = match &inner_response.data {
            Some(data) => {
                let attempt_status =
                    get_status(data.status.to_owned(), data.next_action.to_owned());
                match attempt_status {
                    common_enums::AttemptStatus::Failure => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: data
                                .failure_code
                                .to_owned()
                                .unwrap_or(inner_response.status.error_code.clone()),
                            status_code: item.http_code,
                            message: inner_response.status.status.clone().unwrap_or_default(),
                            reason: data.failure_message.to_owned(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                    _ => {
                        let redirection_url = data
                            .redirect_url
                            .as_ref()
                            .filter(|redirect_str| !redirect_str.is_empty())
                            .map(|url| {
                                Url::parse(url)
                                    .change_context(ConnectorError::FailedToObtainIntegrationUrl)
                            })
                            .transpose()?;

                        let redirection_data =
                            redirection_url.map(|url| RedirectForm::from((url, Method::Get)));

                        (
                            attempt_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(data.id.to_owned()),
                                redirection_data: redirection_data.map(Box::new),
                                mandate_reference: data.payment_method.to_owned().map(|pm_id| {
                                    Box::new(domain_types::connector_types::MandateReference {
                                        connector_mandate_id: Some(pm_id),
                                        payment_method_id: None,
                                        connector_mandate_request_reference_id: None,
                                    })
                                }),
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: data
                                    .merchant_reference_id
                                    .to_owned(),
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                        )
                    }
                }
            }
            None => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: inner_response.status.error_code.clone(),
                    status_code: item.http_code,
                    message: inner_response.status.status.clone().unwrap_or_default(),
                    reason: inner_response.status.message.clone(),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}

// ============== REPEAT PAYMENT (MIT - Merchant Initiated Transaction) ==============
// RepeatPayment: Subsequent transaction using stored payment method
// Uses POST /v1/payments with stored payment_method ID and initiation_type="merchant"

/// Response type for RepeatPayment - reuses RapydPaymentsResponse
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RapydRepeatPaymentResponse(pub RapydPaymentsResponse);

#[derive(Default, Debug, Serialize)]
pub struct RapydRepeatPaymentRequest {
    pub amount: StringMajorUnit,
    pub currency: common_enums::Currency,
    pub payment_method: String,
    pub merchant_reference_id: Option<String>,
    pub capture: Option<bool>,
    pub description: Option<String>,
    pub initiation_type: String,
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<
        RapydRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    > for RapydRepeatPaymentRequest
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: RapydRouterData<
            RouterDataV2<
                RepeatPayment,
                PaymentFlowData,
                RepeatPaymentData<T>,
                PaymentsResponseData,
            >,
            T,
        >,
    ) -> Result<Self, Self::Error> {
        let amount = item
            .connector
            .amount_converter
            .convert(
                item.router_data.request.minor_amount,
                item.router_data.request.currency,
            )
            .change_context(ConnectorError::RequestEncodingFailed)?;

        // Get the stored payment method ID from mandate_reference
        let payment_method_id = match &item.router_data.request.mandate_reference {
            MandateReferenceId::ConnectorMandateId(connector_mandate_ref) => connector_mandate_ref
                .get_connector_mandate_id()
                .ok_or_else(|| {
                    error_stack::report!(ConnectorError::MissingRequiredField {
                        field_name: "connector_mandate_id",
                    })
                })?,
            _ => {
                return Err(error_stack::report!(ConnectorError::NotSupported {
                    message: "Network mandate ID not supported".to_string(),
                    connector: "rapyd",
                }))
            }
        };

        Ok(Self {
            amount,
            currency: item.router_data.request.currency,
            payment_method: payment_method_id,
            capture: Some(true),
            merchant_reference_id: Some(
                item.router_data
                    .resource_common_data
                    .connector_request_reference_id
                    .clone(),
            ),
            description: Some("Repeat payment".to_string()),
            initiation_type: "merchant".to_string(),
        })
    }
}

impl<T: PaymentMethodDataTypes + Debug + Sync + Send + 'static + Serialize>
    TryFrom<ResponseRouterData<RapydRepeatPaymentResponse, Self>>
    for RouterDataV2<RepeatPayment, PaymentFlowData, RepeatPaymentData<T>, PaymentsResponseData>
{
    type Error = error_stack::Report<ConnectorError>;
    fn try_from(
        item: ResponseRouterData<RapydRepeatPaymentResponse, Self>,
    ) -> Result<Self, Self::Error> {
        // Unwrap the inner RapydPaymentsResponse from the wrapper
        let inner_response = &item.response.0;
        let (status, response) = match &inner_response.data {
            Some(data) => {
                let attempt_status =
                    get_status(data.status.to_owned(), data.next_action.to_owned());
                match attempt_status {
                    common_enums::AttemptStatus::Failure => (
                        common_enums::AttemptStatus::Failure,
                        Err(ErrorResponse {
                            code: data
                                .failure_code
                                .to_owned()
                                .unwrap_or(inner_response.status.error_code.clone()),
                            status_code: item.http_code,
                            message: inner_response.status.status.clone().unwrap_or_default(),
                            reason: data.failure_message.to_owned(),
                            attempt_status: None,
                            connector_transaction_id: None,
                            network_advice_code: None,
                            network_decline_code: None,
                            network_error_message: None,
                        }),
                    ),
                    _ => {
                        let redirection_url = data
                            .redirect_url
                            .as_ref()
                            .filter(|redirect_str| !redirect_str.is_empty())
                            .map(|url| {
                                Url::parse(url)
                                    .change_context(ConnectorError::FailedToObtainIntegrationUrl)
                            })
                            .transpose()?;

                        let redirection_data =
                            redirection_url.map(|url| RedirectForm::from((url, Method::Get)));

                        (
                            attempt_status,
                            Ok(PaymentsResponseData::TransactionResponse {
                                resource_id: ResponseId::ConnectorTransactionId(data.id.to_owned()),
                                redirection_data: redirection_data.map(Box::new),
                                mandate_reference: None,
                                connector_metadata: None,
                                network_txn_id: None,
                                connector_response_reference_id: data
                                    .merchant_reference_id
                                    .to_owned(),
                                incremental_authorization_allowed: None,
                                status_code: item.http_code,
                            }),
                        )
                    }
                }
            }
            None => (
                common_enums::AttemptStatus::Failure,
                Err(ErrorResponse {
                    code: inner_response.status.error_code.clone(),
                    status_code: item.http_code,
                    message: inner_response.status.status.clone().unwrap_or_default(),
                    reason: inner_response.status.message.clone(),
                    attempt_status: None,
                    connector_transaction_id: None,
                    network_advice_code: None,
                    network_decline_code: None,
                    network_error_message: None,
                }),
            ),
        };

        Ok(Self {
            resource_common_data: PaymentFlowData {
                status,
                ..item.router_data.resource_common_data
            },
            response,
            ..item.router_data
        })
    }
}
