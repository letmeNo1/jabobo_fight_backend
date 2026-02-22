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

def query_user_by_username(username: str):
    """通过用户名查询用户（独立连接，用完即关）"""
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

def query_user_by_account_id(account_id: int):
    """通过account_id查询用户（适配前端传参）"""
    connection, cursor = get_db_connection()
    try:
        sql = """
            SELECT ua.id as account_id, ua.username, ua.password, ua.role,
                p.id as player_id, p.name as player_name, p.role as player_role
            FROM user_accounts ua
            LEFT JOIN players p ON ua.id = p.account_id
            WHERE ua.id = %s
        """
        cursor.execute(sql, (account_id,))
        user_data = cursor.fetchone()
        if user_data:
            logger.info(f"🔍 [DB] 查询账号ID {account_id} 成功: {user_data}")
        else:
            logger.warning(f"⚠️ [DB] 查询账号ID {account_id} 不存在")
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
    username: str = Field(min_length=3, max_length=50, description="注册账号")
    password: str = Field(min_length=6, max_length=255, description="注册密码")
    player_name: str = Field(default="乐斗小豆", description="游戏角色名")
    role: str = Field(default="Player", description="用户角色（默认普通玩家）")

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

# 简化认证模型：兼容前端平铺传参
class UserAuthRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    account_id: Optional[int] = Field(default=None, description="账号ID")
    username: Optional[str] = Field(default=None, description="用户名")

# ------------------- 核心依赖（终极修复版） -------------------
def get_current_user(
    # 兼容两种传参方式：平铺 account_id/username 或 嵌套 auth_req
    account_id: Optional[int] = Body(default=None),
    username: Optional[str] = Body(default=None),
    auth_req: Optional[UserAuthRequest] = Body(default=None)
):
    """
    终极修复：兼容前端平铺/嵌套两种传参格式
    - 优先取平铺的 account_id/username
    - 其次取 auth_req 中的 account_id/username
    """
    logger.info(f"🔍 [AUTH] 开始校验用户 - 平铺参数: account_id={account_id}, username={username}; 嵌套参数: {auth_req}")
    
    try:
        # 合并参数：优先平铺，其次嵌套
        final_account_id = account_id or (auth_req.account_id if auth_req else None)
        final_username = username or (auth_req.username if auth_req else None)
        
        # 校验参数完整性
        if not final_account_id and not final_username:
            logger.warning(f"⚠️ [AUTH] 未传递账号ID或用户名")
            raise HTTPException(status_code=400, detail="必须传递account_id或username")
        
        # 查询用户
        if final_account_id:
            user = query_user_by_account_id(final_account_id)
        else:
            user = query_user_by_username(final_username)
        
        if not user:
            raise HTTPException(status_code=401, detail="用户不存在")
        
        # 统一角色大小写
        user["role"] = user["role"].upper() if user.get("role") else "PLAYER"
        logger.info(f"✅ [AUTH] 用户 {user['username']} 校验成功（角色：{user['role']}）")
        return user
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ [AUTH] 校验失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"权限校验失败：{str(e)}")

def is_admin(current_user: dict = Depends(get_current_user)):
    """管理员权限校验（修复角色大小写问题）"""
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
        
        # 统一角色大小写
        user["role"] = user["role"].upper()
        logger.success(f"✅ [LOGIN] {req.username} 登录成功")
        return {
            "success": True,
            "data": {
                "account_id": user["account_id"],
                "username": user["username"],
                "player_id": user["player_id"],
                "player_name": user["player_name"],
                "role": user["role"]  # 返回大写角色，前端适配
            }
        }
    finally:
        close_db_connection(connection, cursor)

# 2. 注册接口（完全开放，任何用户都可注册）
@router.post("/auth/register", summary="用户注册（完全开放）")
async def register_user(req: UserRegisterRequest):
    """完全开放注册，普通用户可自由注册，默认角色为Player"""
    logger.info(f"➕ [REGISTER] 注册新用户: {req.username} (角色: {req.role})")
    connection, cursor = get_db_connection()
    
    try:
        # 安全限制：普通用户不能注册ADMIN角色
        if req.role.upper() == "ADMIN":
            logger.warning(f"🚫 [REGISTER] 普通用户尝试注册管理员账号: {req.username}")
            raise HTTPException(status_code=403, detail="禁止直接注册管理员账号")
        
        # 检查用户是否已存在
        cursor.execute("SELECT id FROM user_accounts WHERE username = %s", (req.username,))
        if cursor.fetchone():
            raise HTTPException(status_code=400, detail="账号已存在")
        
        # 插入账号（统一存储大写角色）
        hashed_pwd = req.password  # 明文存储（测试用，生产环境用pwd_context.hash(req.password)）
        user_role = req.role.upper()  # 修复：统一转大写存储
        cursor.execute("""
            INSERT INTO user_accounts (username, password, created_at, role, updated_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (req.username, hashed_pwd, datetime.now(), user_role, datetime.now()))
        account_id = cursor.lastrowid
        
        # 插入玩家数据（统一角色格式）
        cursor.execute("""
            INSERT INTO players (
                name, level, exp, gold, str, agi, spd, maxHp,
                weapons, skills, dressing, unlockedDressings, isConcentrated, friends, account_id, role
            ) VALUES (
                %s, 1, 0, 500, 5, 5, 5, 300,
                '[]', '[]', '{"HEAD":"","BODY":"","WEAPON":""}', '[]', 0, '[]', %s, %s
            )
        """, (req.player_name, account_id, user_role))
        
        connection.commit()
        logger.success(f"✅ [REGISTER] {req.username} 注册成功")
        return {
            "success": True,
            "message": "注册成功",
            "data": {
                "account_id": account_id,
                "username": req.username,
                "player_id": cursor.lastrowid,
                "player_name": req.player_name,
                "role": user_role  # 返回大写角色
            }
        }
    except Error as e:
        connection.rollback()
        logger.error(f"❌ [REGISTER] 失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"注册失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

# 3. 获取服务器玩家列表（终极修复）
@router.post("/player/list", summary="获取服务器玩家列表（修复连接关闭+参数匹配）")
async def get_all_server_players(current_user: dict = Depends(get_current_user)):
    """
    修复点：适配前端平铺传参，优化JSON解析容错
    """
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
        
        # 解析JSON字段（增强容错）
        processed = []
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for p in players:
            item = p.copy()
            for f in json_fields:
                try:
                    # 修复：兼容空值/非JSON字符串
                    if item[f] and isinstance(item[f], str):
                        item[f] = json.loads(item[f])
                    else:
                        item[f] = [] if f != "dressing" else {}
                except Exception as e:
                    logger.warning(f"⚠️ [JSON] 解析 {f} 失败: {str(e)}，使用默认值")
                    item[f] = [] if f != "dressing" else {}
            # 修复：数据库int转bool
            item["isConcentrated"] = bool(item.get("isConcentrated", 0))
            # 统一角色大小写
            item["user_role"] = item["user_role"].upper() if item.get("user_role") else "PLAYER"
            processed.append(item)
        
        logger.success(f"✅ [PLAYER LIST] 返回 {len(processed)} 条数据")
        return {
            "success": True,
            "data": processed  # 统一返回格式：success+data
        }
    except Error as e:
        logger.error(f"❌ [PLAYER LIST] 失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"获取玩家列表失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

# 4. 获取玩家数据（修复：添加权限校验）
@router.get("/player/data", summary="获取玩家数据（新增权限校验）")
async def get_player_data(
    account_id: int = Query(..., description="账号ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    修复点：添加权限校验，仅本人/管理员可查
    """
    # 权限校验
    is_admin = current_user.get("role") == "ADMIN"
    is_self = current_user["account_id"] == account_id
    if not (is_admin or is_self):
        raise HTTPException(status_code=403, detail="无权查看他人数据")
    
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
        
        # 解析JSON（增强容错）
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for f in json_fields:
            try:
                if player[f] and isinstance(player[f], str):
                    player[f] = json.loads(player[f])
                else:
                    player[f] = [] if f != "dressing" else {}
            except:
                player[f] = [] if f != "dressing" else {}
        player["isConcentrated"] = bool(player["isConcentrated"])
        player["role"] = player["role"].upper() if player.get("role") else "PLAYER"
        
        return {
            "success": True,
            "data": player  # 统一返回格式
        }
    finally:
        close_db_connection(connection, cursor)

# 5. 更新玩家数据（修复：统一返回格式，兼容bool/int）
@router.put("/player/update", summary="更新玩家数据（修复返回格式）")
async def update_player_data(
    req: PlayerUpdateRequest, 
    current_user: dict = Depends(get_current_user)
):
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
        simple_fields = ["name", "level", "exp", "gold", "str", "agi", "spd", "maxHp"]
        bool_fields = ["isConcentrated"]  # 单独处理bool字段
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        
        # 处理普通字段
        for f in simple_fields:
            v = getattr(req, f)
            if v is not None:
                update_fields.append(f"{f} = %s")
                params.append(v)
        
        # 修复：bool转int（适配数据库tinyint类型）
        for f in bool_fields:
            v = getattr(req, f)
            if v is not None:
                update_fields.append(f"{f} = %s")
                params.append(1 if v else 0)
        
        # 处理JSON字段
        for f in json_fields:
            v = getattr(req, f)
            if v is not None:
                update_fields.append(f"{f} = %s")
                params.append(json.dumps(v, ensure_ascii=False))
        
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
        logger.success(f"✅ [UPDATE] 账号ID {req.account_id} 更新成功")
        return {
            "success": True,
            "data": None,  # 统一返回格式：success+data
            "message": "更新成功"
        }
    except Error as e:
        connection.rollback()
        logger.error(f"❌ [UPDATE] 失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"更新失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

# 6. 获取所有玩家（管理员）（修复：JSON解析容错）
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
        
        # 解析JSON（增强容错）
        processed = []
        json_fields = ["weapons", "skills", "dressing", "unlockedDressings", "friends"]
        for p in players:
            item = p.copy()
            for f in json_fields:
                try:
                    if item[f] and isinstance(item[f], str):
                        item[f] = json.loads(item[f])
                    else:
                        item[f] = [] if f != "dressing" else {}
                except:
                    item[f] = [] if f != "dressing" else {}
            item["isConcentrated"] = bool(item.get("isConcentrated", 0))
            item["role"] = item["role"].upper() if item.get("role") else "PLAYER"
            processed.append(item)
        
        return {
            "success": True,
            "data": processed
        }
    finally:
        close_db_connection(connection, cursor)

# 7. 重置玩家数据接口（补充缺失的接口）
@router.post("/player/reset", summary="重置玩家数据")
async def reset_player_data(
    account_id: int = Query(..., description="账号ID"),
    current_user: dict = Depends(get_current_user)
):
    # 权限校验
    is_admin = current_user.get("role") == "ADMIN"
    is_self = current_user["account_id"] == account_id
    if not (is_admin or is_self):
        raise HTTPException(status_code=403, detail="无权重置他人数据")
    
    connection, cursor = get_db_connection()
    try:
        # 重置玩家基础数据
        reset_sql = """
            UPDATE players 
            SET level=1, exp=0, gold=500, str=5, agi=5, spd=5, maxHp=300,
                weapons='[]', skills='[]', dressing='{"HEAD":"","BODY":"","WEAPON":""}',
                unlockedDressings='[]', isConcentrated=0, friends='[]'
            WHERE account_id = %s
        """
        cursor.execute(reset_sql, (account_id,))
        
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="玩家不存在")
        
        connection.commit()
        logger.success(f"✅ [RESET] 账号ID {account_id} 数据重置成功")
        return {
            "success": True,
            "message": "玩家数据重置成功"
        }
    except Error as e:
        connection.rollback()
        logger.error(f"❌ [RESET] 失败: {str(e)}")
        raise HTTPException(status_code=500, detail=f"重置数据失败：{str(e)}")
    finally:
        close_db_connection(connection, cursor)

# ------------------- 启动服务 -------------------
if __name__ == "__main__":
    from fastapi import FastAPI
    import uvicorn
    app = FastAPI(title="乐斗游戏API（终极修复版）")
    app.include_router(router)
    # 适配前端默认端口3000
    uvicorn.run(app, host="0.0.0.0", port=8009)