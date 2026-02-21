from fastapi import FastAPI, HTTPException, Depends, Query, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any, Literal
import mysql.connector
from mysql.connector import Error
import json
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import uuid

# ------------------- 基础配置 -------------------
app = FastAPI(title="乐斗游戏核心API", version="1.0")

# 密码加密配置
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT 配置（生产环境请从环境变量读取 SECRET_KEY）
SECRET_KEY = "your-secret-key-1234567890-abcdefghijklmnop"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 120  # 令牌有效期2小时

# OAuth2 令牌验证
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# 数据库连接配置（适配你的 Docker 环境）
DB_CONFIG = {
    "host": "localhost",
    "user": "qfight_user",
    "password": "123456",
    "database": "qfight_db",
    "port": 8008,
    "charset": "utf8mb4"
}

# ------------------- 数据库工具函数 -------------------
def get_db_connection():
    """获取数据库连接"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"数据库连接错误: {e}")
        raise HTTPException(status_code=500, detail="数据库连接失败")

# ------------------- 数据模型定义（Pydantic） -------------------
# 注册请求模型
class UserRegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, description="登录账号（唯一）")
    password: str = Field(min_length=6, max_length=255, description="登录密码")
    player_name: str = Field(default="乐斗小豆", description="玩家昵称")

# 登录响应模型
class Token(BaseModel):
    access_token: str
    token_type: str
    account_id: int
    username: str

# 用户信息模型
class UserInfo(BaseModel):
    account_id: int
    username: str
    created_at: str

# 玩家数据完整模型（和数据库字段一一对应）
class PlayerData(BaseModel):
    player_id: int
    account_id: int
    name: str
    level: int
    exp: int
    gold: int
    str: int
    agi: int
    spd: int
    maxHp: int
    weapons: List[str]
    skills: List[str]
    dressing: Dict[str, str]
    unlockedDressings: List[str]
    isConcentrated: bool
    friends: List[Dict[str, Any]]

# 玩家属性更新模型（支持部分字段更新）
class PlayerUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, description="玩家昵称")
    level: Optional[int] = Field(None, ge=1, description="玩家等级")
    exp: Optional[int] = Field(None, ge=0, description="经验值")
    gold: Optional[int] = Field(None, ge=0, description="金币")
    str: Optional[int] = Field(None, ge=1, description="力量")
    agi: Optional[int] = Field(None, ge=1, description="敏捷")
    spd: Optional[int] = Field(None, ge=1, description="速度")
    maxHp: Optional[int] = Field(None, ge=1, description="最大生命值")
    weapons: Optional[List[str]] = Field(None, description="武器列表")
    skills: Optional[List[str]] = Field(None, description="技能列表")
    dressing: Optional[Dict[str, str]] = Field(None, description="装扮")
    unlockedDressings: Optional[List[str]] = Field(None, description="已解锁装扮")
    isConcentrated: Optional[bool] = Field(None, description="是否专注")
    friends: Optional[List[Dict[str, Any]]] = Field(None, description="好友列表")

# ------------------- 工具函数 -------------------
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """加密密码"""
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """生成JWT令牌"""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """验证令牌，获取当前登录用户"""
    credentials_exception = HTTPException(
        status_code=401,
        detail="令牌无效或已过期",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        account_id: str = payload.get("sub")
        if account_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    # 查询用户信息
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, username FROM user_accounts WHERE id = %s", (account_id,))
        user = cursor.fetchone()
        if user is None:
            raise credentials_exception
        return user
    finally:
        cursor.close()
        connection.close()

# ------------------- 核心接口实现 -------------------
# 1. 用户注册
@app.post("/api/auth/register", summary="用户注册", response_model=Token)
async def register_user(request: UserRegisterRequest):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # 检查账号是否已存在
        cursor.execute("SELECT id FROM user_accounts WHERE username = %s", (request.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="账号已存在")
        
        # 加密密码并插入账号表
        hashed_pwd = get_password_hash(request.password)
        cursor.execute(
            "INSERT INTO user_accounts (username, password) VALUES (%s, %s)",
            (request.username, hashed_pwd)
        )
        account_id = cursor.lastrowid
        
        # 插入默认玩家数据（匹配你的字段结构）
        cursor.execute(
            """
            INSERT INTO players (
                name, level, exp, gold, str, agi, spd, maxHp,
                weapons, skills, dressing, unlockedDressings, isConcentrated, friends, account_id
            ) VALUES (
                %s, 1, 0, 500, 5, 5, 5, 300,
                '[]', '[]', '{"HEAD":"","BODY":"","WEAPON":""}', '[]', 0, '[]', %s
            )
            """,
            (request.player_name, account_id)
        )
        
        connection.commit()
        
        # 生成令牌
        access_token = create_access_token(
            data={"sub": str(account_id)},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "account_id": account_id,
            "username": request.username
        }
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"注册失败：{str(e)}")
    finally:
        cursor.close()
        connection.close()

# 2. 用户登录
@app.post("/api/auth/login", summary="用户登录", response_model=Token)
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # 查询账号信息
        cursor.execute(
            "SELECT id, username, password FROM user_accounts WHERE username = %s",
            (form_data.username,)
        )
        user = cursor.fetchone()
        
        # 验证账号密码
        if not user or not verify_password(form_data.password, user["password"]):
            # 兼容明文密码（你的test_user密码是明文123456）
            if not user or form_data.password != user["password"]:
                raise HTTPException(
                    status_code=401,
                    detail="账号或密码错误",
                    headers={"WWW-Authenticate": "Bearer"},
                )
        
        # 生成令牌
        access_token = create_access_token(
            data={"sub": str(user["id"])},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "account_id": user["id"],
            "username": user["username"]
        }
    finally:
        cursor.close()
        connection.close()

# 3. 获取当前用户信息
@app.get("/api/user/info", summary="获取用户基础信息", response_model=UserInfo)
async def get_user_info(current_user: dict = Depends(get_current_user)):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.execute(
            """
            SELECT id, username, DATE_FORMAT(created_at, '%%Y-%%m-%%d %%H:%%i:%%s') as created_at 
            FROM user_accounts WHERE id = %s
            """,
            (current_user["id"],)
        )
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="用户不存在")
        
        return {
            "account_id": user["id"],
            "username": user["username"],
            "created_at": user["created_at"]
        }
    finally:
        cursor.close()
        connection.close()

# 4. 获取完整玩家数据
@app.get("/api/player/data", summary="获取完整玩家数据", response_model=PlayerData)
async def get_player_data(current_user: dict = Depends(get_current_user)):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        cursor.execute(
            """
            SELECT 
                id as player_id, account_id, name, level, exp, gold, str, agi, spd, maxHp,
                JSON_EXTRACT(weapons, '$') as weapons,
                JSON_EXTRACT(skills, '$') as skills,
                JSON_EXTRACT(dressing, '$') as dressing,
                JSON_EXTRACT(unlockedDressings, '$') as unlockedDressings,
                isConcentrated,
                JSON_EXTRACT(friends, '$') as friends
            FROM players WHERE account_id = %s
            """,
            (current_user["id"],)
        )
        player = cursor.fetchone()
        if not player:
            raise HTTPException(status_code=404, detail="玩家数据不存在")
        
        # 解析JSON字段为Python对象
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for field in json_fields:
            player[field] = json.loads(player[field]) if player[field] else [] if field != "dressing" else {}
        
        # 转换布尔值（数据库中0/1 → false/true）
        player["isConcentrated"] = bool(player["isConcentrated"])
        
        return player
    finally:
        cursor.close()
        connection.close()

# 5. 更新玩家数据（支持部分字段更新）
@app.put("/api/player/update", summary="更新玩家数据", response_model=PlayerData)
async def update_player_data(
    update_data: PlayerUpdateRequest,
    current_user: dict = Depends(get_current_user)
):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)
    
    try:
        # 构建更新SQL（只更新非空字段）
        update_fields = []
        update_params = []
        
        # 处理普通字段
        simple_fields = ["name", "level", "exp", "gold", "str", "agi", "spd", "maxHp", "isConcentrated"]
        for field in simple_fields:
            value = getattr(update_data, field)
            if value is not None:
                update_fields.append(f"{field} = %s")
                update_params.append(value)
        
        # 处理JSON字段
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for field in json_fields:
            value = getattr(update_data, field)
            if value is not None:
                update_fields.append(f"{field} = %s")
                update_params.append(json.dumps(value))
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="无更新字段")
        
        # 执行更新
        update_sql = f"""
            UPDATE players 
            SET {', '.join(update_fields)} 
            WHERE account_id = %s
        """
        update_params.append(current_user["id"])
        cursor.execute(update_sql, update_params)
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="玩家数据不存在")
        
        connection.commit()
        
        # 返回更新后的完整数据
        return await get_player_data(current_user)
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"更新失败：{str(e)}")
    finally:
        cursor.close()
        connection.close()

# 6. 重置玩家数据（可选，用于测试）
@app.post("/api/player/reset", summary="重置玩家数据为初始状态")
async def reset_player_data(current_user: dict = Depends(get_current_user)):
    connection = get_db_connection()
    cursor = connection.cursor()
    
    try:
        cursor.execute(
            """
            UPDATE players 
            SET 
                name = '乐斗小豆', level = 1, exp = 0, gold = 500,
                str = 5, agi = 5, spd = 5, maxHp = 300,
                weapons = '[]', skills = '[]',
                dressing = '{"HEAD":"","BODY":"","WEAPON":""}',
                unlockedDressings = '[]', isConcentrated = 0, friends = '[]'
            WHERE account_id = %s
            """,
            (current_user["id"],)
        )
        connection.commit()
        return {"detail": "玩家数据已重置为初始状态"}
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"重置失败：{str(e)}")
    finally:
        cursor.close()
        connection.close()

# ------------------- 启动服务 -------------------
if __name__ == "__main__":
    import uvicorn
    # 启动服务（0.0.0.0 允许外部访问）
    uvicorn.run(app, host="0.0.0.0", port=8000)