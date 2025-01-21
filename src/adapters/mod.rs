pub mod deckard_llm;
pub mod tyrell;

use deckard_llm::DeckardLLMv1;
use tyrell::TyrellLLMv1;

/// We may not use this at all. The intent was to provide a common interface for the adapters.
pub enum _Adapter {
    DeckardLLMv1(DeckardLLMv1),
    TyrellLLMv1(TyrellLLMv1),
}

impl _Adapter {
    pub fn _new(adapter: &str) -> Self {
        match adapter {
            "deckard_llm_v1" => _Adapter::DeckardLLMv1(DeckardLLMv1::new()),
            "tyrell_llm_v1" => _Adapter::TyrellLLMv1(TyrellLLMv1::new()),
            _ => panic!("Invalid adapter: {}", adapter),
        }
    }
}
