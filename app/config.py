from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str
    JWT_SECRET: str = "cambiar-esto-en-produccion"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_HOURS: int = 24

    class Config:
        env_file = ".env"


settings = Settings()
