from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any, Union
import json
from passlib.context import CryptContext
from loguru import logger
import pymysql
from pymysql import Error
from datetime import datetime

# ------------------- 基础配置 -------------------
router = APIRouter(prefix="/api", tags=["乐斗游戏核心接口（终极修复版）"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ------------------- 数据库工具函数（每次操作新建连接，用完即关） -------------------
def get_db_connection():
    """每次调用新建独立连接，用完必须关闭"""
    connection = None
    cursor = None
    try:
        connection = pymysql.connect(
            host="localhost",       # 替换为你的MySQL地址
            user="qfight_user",     # 替换为你的MySQL用户名
            password="123456",      # 替换为你的MySQL密码
            database="qfight_db",   # 替换为你的数据库名
            port=8008,              # 替换为你的MySQL端口
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor
        )
        cursor = connection.cursor()
        logger.info("✅ [DB] 新建数据库连接成功")
        return connection, cursor
    except Error as e:
        logger.error(f"❌ [DB] 创建连接失败: {str(e)}")
        if connection:
            connection.close()
        raise HTTPException(status_code=500, detail=f"数据库连接失败：{str(e)}")

def close_db_connection(connection, cursor):
    """安全关闭连接和游标"""
    try:
        if cursor:
            cursor.close()
        if connection and connection.open:
            connection.close()
        logger.info("🔌 [DB] 连接已关闭")
    except Error as e:
        logger.error(f"❌ [DB] 关闭连接失败: {str(e)}")

def query_user(username: str):
    """查询用户（独立连接，用完即关）"""
    connection, cursor = get_db_connection()
    try:
        sql = """
            SELECT ua.id as account_id, ua.username, ua.password, ua.role,
                p.id as player_id, p.name as player_name, p.role as player_role
            FROM user_accounts ua
            LEFT JOIN players p ON ua.id = p.account_id
            WHERE ua.username = %s
        """
        cursor.execute(sql, (username,))
        user_data = cursor.fetchone()
        if user_data:
            logger.info(f"🔍 [DB] 查询用户 {username} 成功: {user_data}")
        else:
            logger.warning(f"⚠️ [DB] 查询用户 {username} 不存在")
        return user_data
    except Error as e:
        logger.error(f"❌ [DB] 查询用户失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"查询用户失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """简化版密码验证（明文，测试用）"""
    logger.info(f"🔑 密码验证: 明文={plain_password}, 存储值={hashed_password}")
    return plain_password == hashed_password

# ------------------- 数据模型 -------------------
class UserLoginRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    username: str = Field(description="登录账号")
    password: str = Field(description="登录密码")

class UserRegisterRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=255)
    player_name: str = Field(default="乐斗小豆")
    role: str = Field(default="Player")

class PlayerUpdateRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    account_id: int = Field(description="账号ID")
    name: Optional[str] = None
    level: Optional[int] = Field(default=None, ge=1)
    exp: Optional[int] = Field(default=None, ge=0)
    gold: Optional[int] = Field(default=None, ge=0)
    str: Optional[int] = Field(default=None, ge=1)
    agi: Optional[int] = Field(default=None, ge=1)
    spd: Optional[int] = Field(default=None, ge=1)
    maxHp: Optional[int] = Field(default=None, ge=1)
    weapons: Optional[List[str]] = None
    skills: Optional[List[str]] = None
    dressing: Optional[Dict[str, str]] = None
    unlockedDressings: Optional[List[str]] = None
    isConcentrated: Optional[bool] = None
    friends: Optional[List[Dict[str, Any]]] = None

# ------------------- 核心依赖（终极修复版） -------------------
def get_current_user(
    username: str = Body(..., embed=True, description="当前登录用户名")
):
    """终极修复：独立连接查询，无全局连接冲突"""
    logger.info(f"🔍 [AUTH] 开始校验用户: {username}")
    try:
        # 直接调用独立查询函数（自带连接/关闭逻辑）
        user = query_user(username)
        if not user:
            logger.warning(f"⚠️ [AUTH] 用户 {username} 不存在")
            raise HTTPException(status_code=401, detail=f"用户 {username} 不存在")
        
        logger.info(f"✅ [AUTH] 用户 {username} 校验成功")
        return user
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ [AUTH] 校验失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"权限校验失败：{str(e)}")

def is_admin(current_user: dict = Depends(get_current_user)):
    """管理员权限校验"""
    user_role = current_user.get("role", "").upper()
    if user_role != "ADMIN":
        logger.warning(f"🚫 [AUTH] 非管理员 {current_user['username']} 访问受限接口")
        raise HTTPException(status_code=403, detail="仅管理员可操作")
    return current_user

# ------------------- 核心接口（全部使用独立连接） -------------------
# 1. 登录接口（修复：独立连接，登录不白屏）
@router.post("/auth/login", summary="用户登录（终极修复）")
async def login_user(req: UserLoginRequest):
    logger.info(f"🔓 [LOGIN] 用户 {req.username} 尝试登录")
    connection, cursor = get_db_connection()
    try:
        # 查询用户
        cursor.execute("""
            SELECT ua.id as account_id, ua.username, ua.password, ua.role,
                p.id as player_id, p.name as player_name
            FROM user_accounts ua
            LEFT JOIN players p ON ua.id = p.account_id
            WHERE ua.username = %s
        """, (req.username,))
        user = cursor.fetchone()
        
        # 校验密码
        if not user or not verify_password(req.password, user["password"]):
            logger.warning(f"❌ [LOGIN] 账号/密码错误: {req.username}")
            raise HTTPException(status_code=401, detail="账号或密码错误")
        
        logger.success(f"✅ [LOGIN] {req.username} 登录成功")
        return {
            "success": True,
            "data": {
                "account_id": user["account_id"],
                "username": user["username"],
                "player_id": user["player_id"],
                "player_name": user["player_name"],
                "role": user["role"]
            }
        }
    finally:
        close_db_connection(connection, cursor)

# 2. 注册接口（支持免管理员创建第一个admin）
@router.post("/auth/register", summary="用户注册（免管理员创建第一个admin）")
async def register_user(req: UserRegisterRequest):
    """临时免管理员注册，先创建admin用户"""
    logger.info(f"➕ [REGISTER] 注册新用户: {req.username} (角色: {req.role})")
    connection, cursor = get_db_connection()
    
    try:
        # 检查用户是否已存在
        cursor.execute("SELECT id FROM user_accounts WHERE username = %s", (req.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="账号已存在")
        
        # 插入账号（支持Admin）
        hashed_pwd = req.password  # 明文存储
        cursor.execute("""
            INSERT INTO user_accounts (username, password, created_at, role)
            VALUES (%s, %s, %s, %s)
        """, (req.username, hashed_pwd, datetime.now(), req.role.upper()))
        account_id = cursor.lastrowid
        
        # 插入玩家数据
        cursor.execute("""
            INSERT INTO players (
                name, level, exp, gold, str, agi, spd, maxHp,
                weapons, skills, dressing, unlockedDressings, isConcentrated, friends, account_id, role
            ) VALUES (
                %s, 1, 0, 500, 5, 5, 5, 300,
                '[]', '[]', '{"HEAD":"","BODY":"","WEAPON":""}', '[]', 0, '[]', %s, %s
            )
        """, (req.player_name, account_id, req.role.upper()))
        
        connection.commit()
        logger.success(f"✅ [REGISTER] {req.username} 注册成功")
        return {
            "success": True,
            "message": "注册成功",
            "data": {
                "account_id": account_id,
                "username": req.username,
                "player_id": cursor.lastrowid,
                "player_name": req.player_name
            }
        }
    except Error as e:
        connection.rollback()
        logger.error(f"❌ [REGISTER] 失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"注册失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

# 3. 获取服务器玩家列表（终极修复）
@router.post("/player/list", summary="获取服务器玩家列表（修复连接关闭）")
async def get_all_server_players(current_user: dict = Depends(get_current_user)):
    logger.info(f"🌐 [PLAYER LIST] {current_user['username']} (角色: {current_user['role']}) 查询玩家列表")
    connection, cursor = get_db_connection()
    
    try:
        # 管理员看全部，普通玩家看其他普通玩家
        if current_user.get("role") == "ADMIN":
            cursor.execute("""
                SELECT 
                    p.id, p.account_id, p.name, p.level, p.exp, p.gold,
                    p.str, p.agi, p.spd, p.maxHp, p.weapons, p.skills,
                    p.dressing, p.unlockedDressings, p.isConcentrated, p.friends,
                    ua.role as user_role
                FROM players p
                JOIN user_accounts ua ON p.account_id = ua.id
                ORDER BY p.level DESC
            """)
        else:
            cursor.execute("""
                SELECT 
                    p.id, p.account_id, p.name, p.level, p.exp, p.gold,
                    p.str, p.agi, p.spd, p.maxHp, p.weapons, p.skills,
                    p.dressing, p.unlockedDressings, p.isConcentrated, p.friends,
                    ua.role as user_role
                FROM players p
                JOIN user_accounts ua ON p.account_id = ua.id
                WHERE ua.role = 'PLAYER' AND p.account_id != %s
                ORDER BY p.level DESC
            """, (current_user["account_id"],))
        
        players = cursor.fetchall()
        
        # 解析JSON字段
        processed = []
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for p in players:
            item = p.copy()
            for f in json_fields:
                try:
                    item[f] = json.loads(item[f]) if item[f] else ([] if f != "dressing" else {})
                except:
                    item[f] = [] if f != "dressing" else {}
            item["isConcentrated"] = bool(item.get("isConcentrated", False))
            processed.append(item)
        
        logger.success(f"✅ [PLAYER LIST] 返回 {len(processed)} 条数据")
        return {
            "success": True,
            "data": processed
        }
    except Error as e:
        logger.error(f"❌ [PLAYER LIST] 失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"获取玩家列表失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

# 4. 其他核心接口（保留）
@router.get("/player/data", summary="获取玩家数据")
async def get_player_data(account_id: int = Query(..., description="账号ID")):
    connection, cursor = get_db_connection()
    try:
        cursor.execute("""
            SELECT 
                id as player_id, account_id, name, level, exp, gold, str, agi, spd, maxHp,
                weapons, skills, dressing, unlockedDressings, isConcentrated, friends, role
            FROM players WHERE account_id = %s
        """, (account_id,))
        player = cursor.fetchone()
        if not player:
            raise HTTPException(status_code=404, detail="玩家不存在")
        
        # 解析JSON
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for f in json_fields:
            player[f] = json.loads(player[f]) if player[f] else ([] if f != "dressing" else {})
        player["isConcentrated"] = bool(player["isConcentrated"])
        
        return {
            "success": True,
            "data": player
        }
    finally:
        close_db_connection(connection, cursor)

@router.put("/player/update", summary="更新玩家数据")
async def update_player_data(req: PlayerUpdateRequest, current_user: dict = Depends(get_current_user)):
    # 权限校验
    is_admin = current_user.get("role") == "ADMIN"
    is_self = current_user["account_id"] == req.account_id
    if not (is_admin or is_self):
        raise HTTPException(status_code=403, detail="无权更新他人数据")
    
    connection, cursor = get_db_connection()
    try:
        # 构建更新字段
        update_fields = []
        params = []
        simple_fields = ["name", "level", "exp", "gold", "str", "agi", "spd", "maxHp", "isConcentrated"]
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        
        for f in simple_fields:
            v = getattr(req, f)
            if v is not None:
                update_fields.append(f"{f} = %s")
                params.append(v)
        
        for f in json_fields:
            v = getattr(req, f)
            if v is not None:
                update_fields.append(f"{f} = %s")
                params.append(json.dumps(v))
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="无更新字段")
        
        # 执行更新
        params.append(req.account_id)
        cursor.execute(f"""
            UPDATE players SET {', '.join(update_fields)} WHERE account_id = %s
        """, params)
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="玩家不存在")
        
        connection.commit()
        return {
            "success": True,
            "message": "更新成功"
        }
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"更新失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

@router.post("/player/all", summary="获取所有玩家（管理员）")
async def get_all_players(current_user: dict = Depends(is_admin)):
    connection, cursor = get_db_connection()
    try:
        cursor.execute("""
            SELECT 
                p.id, p.account_id, p.name, p.level, exp, gold, str, agi, spd, maxHp,
                weapons, skills, dressing, unlockedDressings, isConcentrated, friends,
                p.role, ua.created_at, ua.updated_at
            FROM players p
            LEFT JOIN user_accounts ua ON p.account_id = ua.id
        """)
        players = cursor.fetchall()
        
        # 解析JSON
        processed = []
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for p in players:
            item = p.copy()
            for f in json_fields:
                item[f] = json.loads(item[f]) if item[f] else ([] if f != "dressing" else {})
            item["isConcentrated"] = bool(item.get("isConcentrated", False))
            processed.append(item)
        
        return {
            "success": True,
            "data": processed
        }
    finally:
        close_db_connection(connection, cursor)

# ------------------- 启动服务 -------------------
if __name__ == "__main__":
    from fastapi import FastAPI
    import uvicorn
    app = FastAPI(title="乐斗游戏API（终极修复版）")
    app.include_router(router)
    uvicorn.run(app, host="0.0.0.0", port=8009)