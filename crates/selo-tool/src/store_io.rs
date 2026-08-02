use selo_core::store::StoreState;
use std::fs;
use std::path::Path;

const STORE_FILE: &str = ".selo_store.json";

pub fn load_store() -> StoreState {
    if !Path::new(STORE_FILE).exists() {
        return StoreState::new();
    }

    let data = fs::read_to_string(STORE_FILE).unwrap_or_else(|_| "{}".to_string());
    serde_json::from_str(&data).unwrap_or_else(|_| StoreState::new())
}

pub fn save_store(store: &StoreState) -> Result<(), String> {
    let json = serde_json::to_string_pretty(store).map_err(|e| e.to_string())?;
    fs::write(STORE_FILE, json).map_err(|e| e.to_string())
}
