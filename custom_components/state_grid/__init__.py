from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .data_client import StateGridDataClient
from .utils.store import async_load_from_store


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry) -> bool:
    """Set up this integration using UI."""
    config = await async_load_from_store(hass, "state_grid.config") or None
    hass.data[DOMAIN] = StateGridDataClient(hass=hass, config=config)
    hass.async_create_task(hass.config_entries.async_forward_entry_setup(config_entry, Platform.SENSOR))
    return True
