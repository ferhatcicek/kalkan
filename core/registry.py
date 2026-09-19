import importlib
import inspect
import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from core.base import BaseModule, ModuleInfo

logger = logging.getLogger("cyberaudit.registry")
BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_FILE = BASE_DIR / "config.json"


class ModuleRegistry:
    """
    Güvenlik denetim modüllerini dinamik olarak keşfeden, yapılandıran ve yöneten sınıf.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(ModuleRegistry, cls).__new__(cls, *args, **kwargs)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._modules: Dict[str, BaseModule] = {}
        self._config: Dict[str, bool] = {}
        self._load_config()
        self.discover_modules()
        self._initialized = True

    def _load_config(self):
        """Kalıcı config.json dosyasından modül aktiflik durumlarını yükler."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    self._config = json.load(f).get("modules", {})
            except Exception as e:
                logger.error(f"Config dosyası okunamadı: {e}")
                self._config = {}
        else:
            self._config = {}

    def _save_config(self):
        """Modül yapılandırmasını config.json dosyasına kaydeder."""
        try:
            data = {"modules": {m_id: mod.enabled for m_id, mod in self._modules.items()}}
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Config dosyası kaydedilemedi: {e}")

    def discover_modules(self, modules_dir: str = "core/modules"):
        """
        modules_dir dizinindeki tüm mod_*.py dosyalarını dinamik olarak içe aktarır
        ve BaseModule türevlerini kaydeder.
        """
        base_path = BASE_DIR / modules_dir
        if not base_path.exists():
            base_path.mkdir(parents=True, exist_ok=True)
            return

        for py_file in base_path.glob("mod_*.py"):
            module_name = f"core.modules.{py_file.stem}"
            try:
                if module_name in sys.modules:
                    mod = importlib.reload(sys.modules[module_name])
                else:
                    mod = importlib.import_module(module_name)

                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if (
                        inspect.isclass(attr)
                        and issubclass(attr, BaseModule)
                        and attr is not BaseModule
                    ):
                        instance: BaseModule = attr()
                        # Eğer config dosyasında önceden kaydedilmiş durum varsa uygula
                        if instance.id in self._config:
                            instance.enabled = self._config[instance.id]
                        else:
                            self._config[instance.id] = True
                            instance.enabled = True
                        self._modules[instance.id] = instance
                        logger.info(f"Modül keşfedildi ve kaydedildi: {instance.id} ({instance.name})")
            except Exception as e:
                logger.error(f"{module_name} yüklenirken hata oluştu: {e}")

        # Mevcut durumu kaydet
        self._save_config()

    def get_all_modules(self) -> List[BaseModule]:
        """Tüm kayıtlı modülleri liste olarak döner."""
        return list(self._modules.values())

    def get_active_modules(self) -> List[BaseModule]:
        """Yalnızca aktif (enabled=True) olan modülleri döner."""
        return [m for m in self._modules.values() if m.enabled]

    def get_module(self, module_id: str) -> Optional[BaseModule]:
        """Belirtilen ID'ye sahip modülü döner."""
        return self._modules.get(module_id)

    def toggle_module(self, module_id: str, enabled: bool) -> bool:
        """Modülün durumunu aktif veya pasif yapar ve diske yazar."""
        if module_id in self._modules:
            self._modules[module_id].enabled = enabled
            self._config[module_id] = enabled
            self._save_config()
            return True
        return False

    def get_modules_info(self) -> List[ModuleInfo]:
        """Tüm modüllerin ModuleInfo modellerini döner."""
        return [m.get_info() for m in self._modules.values()]
