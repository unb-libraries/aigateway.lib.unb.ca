pub mod deckard_llm;

use deckard_llm::DeckardLLMv1;

pub enum _Adapter {
    DeckardLLMv1(DeckardLLMv1),
}

impl _Adapter {
    pub fn _new(adapter: &str) -> Self {
        match adapter {
            "deckard_llm_v1" => _Adapter::DeckardLLMv1(DeckardLLMv1::new()),
            _ => panic!("Invalid adapter: {}", adapter),
        }
    }
}
