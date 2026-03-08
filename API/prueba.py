import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.logic.managers import AegisManager
from src.logic.managers import UserManager  # ajusta el import a tu estructura

# Obtén el usuario como ya lo estás haciendo
user_manager = UserManager()
user = user_manager.get_user_by_id(1)

manager = AegisManager(user=user)

# Envuelve la corutina en asyncio.run()


result = manager.generate(
        topic_id=30,
        tweaks={
            "company":          "EMESA",
            "sector":           "distribucion_it",
            "audienceLevel":    "mixed",
            "associatedBrands": ["HPE", "Sonicwall", "HP"],
            "mentionContact":   "ciberseguridad@emesa.com",
            "language":         "es",
            "tone":             "formal",
        }
    )

print(result)




