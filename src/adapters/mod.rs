pub mod generic;
pub mod deckard;
pub mod tyrell;
pub mod sebastian;

use generic::GenericInferenceEndpointAdapter;
use deckard::DeckardLLMv1;
use sebastian::SebastianLLMv1;
use tyrell::TyrellLLMv1;

/// We may not use this at all. The intent was to provide a common interface for the adapters.
pub enum _Adapter {
    DeckardLLMv1(DeckardLLMv1),
    SebastianLLMv1(SebastianLLMv1),
    TyrellLLMv1(TyrellLLMv1),
}

impl _Adapter {
    pub fn _new(adapter: &str) -> Self {
        match adapter {
            "deckard_llm_v1" => _Adapter::DeckardLLMv1(DeckardLLMv1::new()),
            "tyrell_llm_v1" => _Adapter::TyrellLLMv1(TyrellLLMv1::new()),
            "sebastian_llm_v1" => _Adapter::SebastianLLMv1(SebastianLLMv1::new()),
            _ => panic!("Invalid adapter: {}", adapter),
        }
    }
}
