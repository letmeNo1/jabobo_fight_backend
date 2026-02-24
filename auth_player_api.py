from fastapi import APIRouter, HTTPException, Depends, Query, Body
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any, Union
import json
from passlib.context import CryptContext
from loguru import logger
import pymysql
from pymysql import Error
from datetime import datetime
import time  # 新增：用于记录耗时

# ------------------- 基础配置 -------------------
router = APIRouter(prefix="/api", tags=["乐斗游戏核心接口（终极修复版）"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 配置loguru日志格式（增强可读性）
logger.remove()  # 移除默认配置
logger.add(
    sink="qfight_api.log",  # 输出到文件
    rotation="500 MB",      # 日志文件大小限制
    retention="7 days",     # 日志保留时间
    compression="zip",      # 压缩旧日志
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {module}:{function}:{line} | {message}",
    level="DEBUG"
)
# 同时输出到控制台
logger.add(
    sink=lambda msg: print(msg, end=""),
    format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
    level="INFO"
)

# ------------------- 数据库工具函数 -------------------
def get_db_connection():
    """每次调用新建独立连接，用完必须关闭"""
    start_time = time.time()
    connection = None
    cursor = None
    try:
        connection = pymysql.connect(
            host="localhost",       
            user="qfight_user",     
            password="123456",      
            database="qfight_db",   
            port=8008,              
            charset="utf8mb4",
            cursorclass=pymysql.cursors.DictCursor
        )
        cursor = connection.cursor()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.info(f"✅ [DB] 新建数据库连接成功 | 耗时: {elapsed}ms | 线程ID: {id(connection)}")
        return connection, cursor
    except Error as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [DB] 创建连接失败 | 耗时: {elapsed}ms | 错误: {str(e)}")
        if connection:
            connection.close()
        raise HTTPException(status_code=500, detail=f"数据库连接失败：{str(e)}")

def close_db_connection(connection, cursor):
    """安全关闭连接和游标"""
    start_time = time.time()
    try:
        if cursor:
            cursor.close()
        if connection and connection.open:
            connection.close()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.info(f"🔌 [DB] 连接已关闭 | 耗时: {elapsed}ms | 线程ID: {id(connection) if connection else 'N/A'}")
    except Error as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [DB] 关闭连接失败 | 耗时: {elapsed}ms | 错误: {str(e)}")

def query_user_by_username(username: str):
    """根据用户名查询用户信息"""
    start_time = time.time()
    logger.debug(f"🔍 [DB] 开始查询用户 | 用户名: {username}")
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
        
        elapsed = round((time.time() - start_time) * 1000, 2)
        if user_data:
            logger.info(f"✅ [DB] 查询用户成功 | 用户名: {username} | account_id: {user_data.get('account_id')} | 耗时: {elapsed}ms")
            # 脱敏日志（隐藏密码）
            safe_user_data = {k: v for k, v in user_data.items() if k != 'password'}
            logger.debug(f"📝 [DB] 用户详情: {json.dumps(safe_user_data, ensure_ascii=False)}")
        else:
            logger.warning(f"⚠️ [DB] 查询用户失败 | 用户名: {username} | 原因: 用户不存在 | 耗时: {elapsed}ms")
        
        return user_data
    finally:
        close_db_connection(connection, cursor)

def query_user_by_account_id(account_id: int):
    """根据账号ID查询用户信息"""
    start_time = time.time()
    logger.debug(f"🔍 [DB] 开始查询用户 | account_id: {account_id}")
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
        
        elapsed = round((time.time() - start_time) * 1000, 2)
        if user_data:
            logger.info(f"✅ [DB] 查询用户成功 | account_id: {account_id} | 用户名: {user_data.get('username')} | 耗时: {elapsed}ms")
            # 脱敏日志
            safe_user_data = {k: v for k, v in user_data.items() if k != 'password'}
            logger.debug(f"📝 [DB] 用户详情: {json.dumps(safe_user_data, ensure_ascii=False)}")
        else:
            logger.warning(f"⚠️ [DB] 查询用户失败 | account_id: {account_id} | 原因: 用户不存在 | 耗时: {elapsed}ms")
        
        return user_data
    finally:
        close_db_connection(connection, cursor)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """验证密码（日志增强）"""
    # 注意：不在日志中记录密码相关信息！
    result = plain_password == hashed_password
    logger.debug(f"🔐 [AUTH] 密码验证 | 结果: {'成功' if result else '失败'}")
    return result

# ------------------- 数据模型 -------------------
class UserLoginRequest(BaseModel):
    username: str
    password: str

class UserRegisterRequest(BaseModel):
    username: str
    password: str
    player_name: str = "乐斗小豆"
    role: str = "Player"

class PlayerUpdateRequest(BaseModel):
    account_id: int
    name: Optional[str] = None
    level: Optional[int] = None
    exp: Optional[int] = None
    gold: Optional[int] = None
    str: Optional[int] = None
    agi: Optional[int] = None
    spd: Optional[int] = None
    maxHp: Optional[int] = None
    weapons: Optional[List[str]] = None
    skills: Optional[List[str]] = None
    dressing: Optional[Dict[str, str]] = None
    unlockedDressings: Optional[List[str]] = None
    isConcentrated: Optional[bool] = None
    friends: Optional[List[Dict[str, Any]]] = None

class UserAuthRequest(BaseModel):
    account_id: Optional[int] = None
    username: Optional[str] = None

# ------------------- 核心依赖 -------------------
def get_current_user(
    account_id: Optional[int] = Body(default=None),
    username: Optional[str] = Body(default=None),
    auth_req: Optional[UserAuthRequest] = Body(default=None)
):
    """兼容前端 Body 传参的权限校验（日志增强）"""
    start_time = time.time()
    final_account_id = account_id or (auth_req.account_id if auth_req else None)
    final_username = username or (auth_req.username if auth_req else None)
    
    logger.debug(f"🔍 [AUTH] 开始权限校验 | account_id: {final_account_id} | username: {final_username}")
    
    if not final_account_id and not final_username:
        logger.error(f"❌ [AUTH] 权限校验失败 | 原因: 缺少account_id和username | 耗时: {round((time.time() - start_time)*1000,2)}ms")
        raise HTTPException(status_code=400, detail="必须传递account_id或username")
    
    try:
        if final_account_id:
            user = query_user_by_account_id(final_account_id)
        else:
            user = query_user_by_username(final_username)
        
        if not user:
            logger.warning(f"⚠️ [AUTH] 权限校验失败 | account_id: {final_account_id} | username: {final_username} | 原因: 用户不存在 | 耗时: {round((time.time() - start_time)*1000,2)}ms")
            raise HTTPException(status_code=401, detail="用户不存在")
        
        user["role"] = user["role"].upper() if user.get("role") else "PLAYER"
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.info(f"✅ [AUTH] 权限校验成功 | account_id: {user['account_id']} | 用户名: {user['username']} | 角色: {user['role']} | 耗时: {elapsed}ms")
        
        return user
    except Exception as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [AUTH] 权限校验异常 | account_id: {final_account_id} | username: {final_username} | 错误: {str(e)} | 耗时: {elapsed}ms")
        raise

def is_admin(current_user: dict = Depends(get_current_user)):
    """管理员权限校验（日志增强）"""
    start_time = time.time()
    logger.debug(f"🔍 [AUTH] 开始管理员权限校验 | account_id: {current_user['account_id']} | 当前角色: {current_user.get('role')}")
    
    if current_user.get("role", "").upper() != "ADMIN":
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.warning(f"⚠️ [AUTH] 管理员权限校验失败 | account_id: {current_user['account_id']} | 当前角色: {current_user.get('role')} | 耗时: {elapsed}ms")
        raise HTTPException(status_code=403, detail="仅管理员可操作")
    
    elapsed = round((time.time() - start_time) * 1000, 2)
    logger.info(f"✅ [AUTH] 管理员权限校验成功 | account_id: {current_user['account_id']} | 耗时: {elapsed}ms")
    return current_user

# ------------------- 核心接口 -------------------

@router.post("/auth/login")
async def login_user(req: UserLoginRequest):
    """用户登录接口（日志增强）"""
    start_time = time.time()
    logger.info(f"📥 [API] 收到登录请求 | 用户名: {req.username} | 时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    connection, cursor = get_db_connection()
    try:
        cursor.execute("""
            SELECT ua.id as account_id, ua.username, ua.password, ua.role,
                p.id as player_id, p.name as player_name
            FROM user_accounts ua
            LEFT JOIN players p ON ua.id = p.account_id
            WHERE ua.username = %s
        """, (req.username,))
        user = cursor.fetchone()
        
        if not user or not verify_password(req.password, user["password"]):
            elapsed = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"❌ [API] 登录失败 | 用户名: {req.username} | 原因: 账号或密码错误 | 耗时: {elapsed}ms")
            raise HTTPException(status_code=401, detail="账号或密码错误")
        
        user["role"] = user["role"].upper()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.success(f"✅ [API] 登录成功 | account_id: {user['account_id']} | 用户名: {req.username} | 角色: {user['role']} | 耗时: {elapsed}ms")
        
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
    except HTTPException:
        raise
    except Exception as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 登录异常 | 用户名: {req.username} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise HTTPException(status_code=500, detail="服务器内部错误")
    finally:
        close_db_connection(connection, cursor)

@router.post("/auth/register")
async def register_user(req: UserRegisterRequest):
    """用户注册接口（日志增强）"""
    start_time = time.time()
    logger.info(f"📥 [API] 收到注册请求 | 用户名: {req.username} | 角色: {req.role} | 角色名: {req.player_name}")
    
    connection, cursor = get_db_connection()
    try:
        if req.role.upper() == "ADMIN":
            elapsed = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"⚠️ [API] 注册失败 | 用户名: {req.username} | 原因: 禁止注册管理员账号 | 耗时: {elapsed}ms")
            raise HTTPException(status_code=403, detail="禁止直接注册管理员账号")
        
        # 检查用户名是否存在
        cursor.execute("SELECT id FROM user_accounts WHERE username = %s", (req.username,))
        if cursor.fetchone():
            elapsed = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"⚠️ [API] 注册失败 | 用户名: {req.username} | 原因: 账号已存在 | 耗时: {elapsed}ms")
            raise HTTPException(status_code=400, detail="账号已存在")
        
        # 创建账号
        user_role = req.role.upper()
        cursor.execute("""
            INSERT INTO user_accounts (username, password, created_at, role, updated_at)
            VALUES (%s, %s, %s, %s, %s)
        """, (req.username, req.password, datetime.now(), user_role, datetime.now()))
        account_id = cursor.lastrowid
        logger.debug(f"📝 [DB] 创建账号成功 | account_id: {account_id} | 用户名: {req.username}")
        
        # 创建玩家数据
        cursor.execute("""
            INSERT INTO players (
                name, level, exp, gold, str, agi, spd, maxHp,
                weapons, skills, dressing, unlockedDressings, isConcentrated, friends, account_id, role
            ) VALUES (
                %s, 1, 0, 500, 5, 5, 5, 300,
                '[]', '[]', '{"HEAD":"","BODY":"","WEAPON":""}', '[]', 0, '[]', %s, %s
            )
        """, (req.player_name, account_id, user_role))
        logger.debug(f"📝 [DB] 创建玩家数据成功 | account_id: {account_id} | 角色名: {req.player_name}")
        
        connection.commit()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.success(f"✅ [API] 注册成功 | account_id: {account_id} | 用户名: {req.username} | 耗时: {elapsed}ms")
        
        return {"success": True, "message": "注册成功", "data": {"account_id": account_id}}
    except HTTPException:
        raise
    except Error as e:
        connection.rollback()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 注册数据库异常 | 用户名: {req.username} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        connection.rollback()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 注册未知异常 | 用户名: {req.username} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise HTTPException(status_code=500, detail="服务器内部错误")
    finally:
        close_db_connection(connection, cursor)

@router.post("/player/list")
async def get_all_server_players(current_user: dict = Depends(get_current_user)):
    """获取服务器玩家列表（日志增强）"""
    start_time = time.time()
    logger.info(f"📥 [API] 收到获取玩家列表请求 | 操作人: {current_user['account_id']} | 角色: {current_user['role']}")
    
    connection, cursor = get_db_connection()
    try:
        if current_user.get("role") == "ADMIN":
            cursor.execute("SELECT p.*, ua.role as user_role FROM players p JOIN user_accounts ua ON p.account_id = ua.id")
            logger.debug(f"📝 [DB] 管理员查询所有玩家 | 操作人: {current_user['account_id']}")
        else:
            cursor.execute("SELECT p.*, ua.role as user_role FROM players p JOIN user_accounts ua ON p.account_id = ua.id WHERE ua.role = 'PLAYER' AND p.account_id != %s", (current_user["account_id"],))
            logger.debug(f"📝 [DB] 普通玩家查询其他玩家 | 操作人: {current_user['account_id']}")
        
        players = cursor.fetchall()
        # 处理JSON字段
        for p in players:
            for f in ["weapons", "skills", "dressing", "unlockedDressings", "friends"]:
                p[f] = json.loads(p[f]) if p[f] else ([] if f != "dressing" else {})
            p["isConcentrated"] = bool(p["isConcentrated"])
            p["user_role"] = p["user_role"].upper()
        
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.info(f"✅ [API] 获取玩家列表成功 | 操作人: {current_user['account_id']} | 玩家数量: {len(players)} | 耗时: {elapsed}ms")
        logger.debug(f"📝 [API] 玩家列表详情: {json.dumps(players, ensure_ascii=False, default=str)[:500]}...")  # 截断长日志
        
        return {"success": True, "data": players}
    except Exception as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 获取玩家列表异常 | 操作人: {current_user['account_id']} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise HTTPException(status_code=500, detail="获取玩家列表失败")
    finally:
        close_db_connection(connection, cursor)

# --- 重点修改接口 1: GET 改为 POST，Query 改为 Body ---
@router.post("/player/data")
async def get_player_data(
    account_id: int = Body(..., embed=True), 
    current_user: dict = Depends(get_current_user)
):
    """获取玩家数据（日志增强）"""
    start_time = time.time()
    logger.info(f"📥 [API] 收到获取玩家数据请求 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 操作人角色: {current_user['role']}")
    
    # 权限校验
    if current_user.get("role") != "ADMIN" and current_user["account_id"] != account_id:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.warning(f"⚠️ [API] 获取玩家数据失败 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 原因: 无权查看他人数据 | 耗时: {elapsed}ms")
        raise HTTPException(status_code=403, detail="无权查看他人数据")
    
    connection, cursor = get_db_connection()
    try:
        cursor.execute("SELECT * FROM players WHERE account_id = %s", (account_id,))
        player = cursor.fetchone()
        
        if not player:
            elapsed = round((time.time() - start_time) * 1000, 2)
            logger.warning(f"⚠️ [API] 获取玩家数据失败 | 目标ID: {account_id} | 原因: 玩家不存在 | 耗时: {elapsed}ms")
            raise HTTPException(status_code=404, detail="玩家不存在")
        
        # 处理JSON字段
        for f in ["weapons", "skills", "dressing", "unlockedDressings", "friends"]:
            player[f] = json.loads(player[f]) if player[f] else ([] if f != "dressing" else {})
        player["isConcentrated"] = bool(player["isConcentrated"])
        
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.info(f"✅ [API] 获取玩家数据成功 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 耗时: {elapsed}ms")
        logger.debug(f"📝 [API] 玩家数据详情: {json.dumps(player, ensure_ascii=False, default=str)}")
        
        return {"success": True, "data": player}
    except HTTPException:
        raise
    except Exception as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 获取玩家数据异常 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise HTTPException(status_code=500, detail="获取玩家数据失败")
    finally:
        close_db_connection(connection, cursor)

@router.put("/player/update")
async def update_player_data(req: PlayerUpdateRequest, current_user: dict = Depends(get_current_user)):
    """更新玩家数据（日志增强）"""
    start_time = time.time()
    logger.info(f"📥 [API] 收到更新玩家数据请求 | 目标ID: {req.account_id} | 操作人: {current_user['account_id']} | 操作人角色: {current_user['role']}")
    
    # 权限校验
    if current_user.get("role") != "ADMIN" and current_user["account_id"] != req.account_id:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.warning(f"⚠️ [API] 更新玩家数据失败 | 目标ID: {req.account_id} | 操作人: {current_user['account_id']} | 原因: 无权更新他人数据 | 耗时: {elapsed}ms")
        raise HTTPException(status_code=403, detail="无权更新他人数据")
    
    # 记录要更新的字段
    update_fields_list = [f for f, v in req.model_dump(exclude={"account_id"}).items() if v is not None]
    logger.debug(f"📝 [API] 准备更新字段 | 目标ID: {req.account_id} | 字段列表: {update_fields_list}")
    logger.debug(f"📝 [API] 更新数据详情: {json.dumps(req.model_dump(), ensure_ascii=False, default=str)}")
    
    connection, cursor = get_db_connection()
    try:
        update_fields = []
        params = []
        for f, v in req.model_dump(exclude={"account_id"}).items():
            if v is not None:
                update_fields.append(f"{f} = %s")
                # 处理JSON字段和布尔值
                params.append(json.dumps(v) if isinstance(v, (list, dict)) else (1 if isinstance(v, bool) and v else (0 if isinstance(v, bool) else v)))
        
        if not update_fields:
            elapsed = round((time.time() - start_time) * 1000, 2)
            logger.info(f"ℹ️ [API] 更新玩家数据跳过 | 目标ID: {req.account_id} | 原因: 无更新字段 | 耗时: {elapsed}ms")
            return {"success": True}
        
        # 执行更新
        params.append(req.account_id)
        sql = f"UPDATE players SET {', '.join(update_fields)} WHERE account_id = %s"
        cursor.execute(sql, params)
        affected_rows = cursor.rowcount
        connection.commit()
        
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.success(f"✅ [API] 更新玩家数据成功 | 目标ID: {req.account_id} | 影响行数: {affected_rows} | 更新字段数: {len(update_fields)} | 耗时: {elapsed}ms")
        
        return {"success": True}
    except Exception as e:
        connection.rollback()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 更新玩家数据异常 | 目标ID: {req.account_id} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise HTTPException(status_code=500, detail="更新玩家数据失败")
    finally:
        close_db_connection(connection, cursor)

@router.post("/player/all")
async def get_all_players_admin(current_user: dict = Depends(is_admin)):
    """管理员获取所有玩家（日志增强）"""
    start_time = time.time()
    logger.info(f"📥 [API] 管理员获取所有玩家 | 操作人: {current_user['account_id']}")
    
    try:
        result = await get_all_server_players(current_user)
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.success(f"✅ [API] 管理员获取所有玩家成功 | 操作人: {current_user['account_id']} | 耗时: {elapsed}ms")
        return result
    except Exception as e:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 管理员获取所有玩家异常 | 操作人: {current_user['account_id']} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise

# --- 重点修改接口 2: Query 改为 Body ---
@router.post("/player/reset")
async def reset_player_data(
    account_id: int = Body(..., embed=True), 
    current_user: dict = Depends(get_current_user)
):
    """重置玩家数据（日志增强）"""
    start_time = time.time()
    logger.info(f"📥 [API] 收到重置玩家数据请求 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 操作人角色: {current_user['role']}")
    
    # 权限校验
    if current_user.get("role") != "ADMIN" and current_user["account_id"] != account_id:
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.warning(f"⚠️ [API] 重置玩家数据失败 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 原因: 无权重置他人数据 | 耗时: {elapsed}ms")
        raise HTTPException(status_code=403, detail="无权重置他人数据")
    
    connection, cursor = get_db_connection()
    try:
        # 执行重置
        cursor.execute("""
            UPDATE players SET level=1, exp=0, gold=500, str=5, agi=5, spd=5, maxHp=300,
            weapons='[]', skills='[]', dressing='{"HEAD":"","BODY":"","WEAPON":""}',
            unlockedDressings='[]', isConcentrated=0, friends='[]'
            WHERE account_id = %s
        """, (account_id,))
        affected_rows = cursor.rowcount
        connection.commit()
        
        elapsed = round((time.time() - start_time) * 1000, 2)
        if affected_rows > 0:
            logger.success(f"✅ [API] 重置玩家数据成功 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 影响行数: {affected_rows} | 耗时: {elapsed}ms")
            return {"success": True, "message": "重置成功"}
        else:
            logger.warning(f"⚠️ [API] 重置玩家数据无变化 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 耗时: {elapsed}ms")
            return {"success": True, "message": "玩家数据无变化（可能不存在）"}
    except Exception as e:
        connection.rollback()
        elapsed = round((time.time() - start_time) * 1000, 2)
        logger.error(f"❌ [API] 重置玩家数据异常 | 目标ID: {account_id} | 操作人: {current_user['account_id']} | 错误: {str(e)} | 耗时: {elapsed}ms", exc_info=True)
        raise HTTPException(status_code=500, detail="重置玩家数据失败")
    finally:
        close_db_connection(connection, cursor)

if __name__ == "__main__":
    from fastapi import FastAPI
    import uvicorn
    app = FastAPI(title="乐斗游戏API", description="乐斗游戏后端API（增强日志版）", version="1.0.0")
    app.include_router(router)
    
    logger.info("🚀 启动乐斗游戏API服务器 | 地址: 0.0.0.0:8009")
    uvicorn.run(app, host="0.0.0.0", port=8009) 帮我写一个脚本脱离命令行之后还能继续使用