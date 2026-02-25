from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from datetime import datetime, timedelta
import pymysql
import json
import os
from dotenv import load_dotenv
from typing import Optional, List, Dict, Any

# 加载配置
load_dotenv()
app = FastAPI(title="乐斗游戏 - 管理员批量修改版", version="1.0")

# CORS（解决前端跨域）
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 内部测试允许所有来源
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT配置
SECRET_KEY = os.getenv("SECRET_KEY", "test-key-123456")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ---------------------- 数据库连接 ----------------------
def get_db():
    return pymysql.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT")),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
        charset="utf8mb4"
    )

# ---------------------- 核心工具函数 ----------------------
def create_access_token(data: dict):
    """生成JWT令牌（包含用户名+角色）"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_info(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """验证令牌，返回当前用户信息（用户名+角色）"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role", "Player")  # Player/Admin
        if username is None:
            raise HTTPException(status_code=401, detail="登录失效")
        return {"username": username, "role": role}
    except JWTError:
        raise HTTPException(status_code=401, detail="登录失效，请重新登录")

def is_admin(current_user: Dict[str, Any] = Depends(get_current_user_info)) -> bool:
    """校验是否为管理员"""
    if current_user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="仅管理员可调用该接口")
    return True

def get_player_id(username: str) -> int:
    """通过用户名获取玩家ID"""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT p.id FROM players p
        JOIN user_accounts u ON p.account_id = u.id
        WHERE u.username = %s
    """, (username,))
    res = cursor.fetchone()
    cursor.close()
    conn.close()
    if not res:
        raise HTTPException(404, f"玩家 {username} 不存在")
    return res[0]

# ---------------------- 请求模型 ----------------------
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)
    role: str = Field("Player", pattern="^(Player|Admin)$")  # 注册时可指定角色

class PasswordChange(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=6)

# 普通玩家修改自己的模型（单字段/分批）
class PlayerSelfUpdate(BaseModel):
    add_level: int = Field(0, ge=0)
    add_maxHp: int = Field(0, ge=0)
    add_gold: int = Field(0, ge=0)
    add_win: int = Field(0, ge=0)
    add_lose: int = Field(0, ge=0)
    weapons: Optional[List[str]] = None
    skills: Optional[List[str]] = None
    dressing: Optional[Dict[str, str]] = None

# 管理员批量修改任意玩家的模型（一次性传所有属性）
class AdminBatchUpdate(BaseModel):
    target_username: str = Field(..., description="要修改的目标玩家用户名")
    level: Optional[int] = Field(None, ge=1)  # 直接设置等级（非增量）
    maxHp: Optional[int] = Field(None, ge=1)  # 直接设置血量
    gold: Optional[int] = Field(None, ge=0)   # 直接设置金币
    win_count: Optional[int] = Field(None, ge=0)  # 直接设置胜场
    lose_count: Optional[int] = Field(None, ge=0) # 直接设置负场
    weapons: Optional[List[str]] = None       # 直接覆盖武器列表
    skills: Optional[List[str]] = None        # 直接覆盖技能列表
    dressing: Optional[Dict[str, str]] = None # 直接覆盖装扮

# ---------------------- 1. 基础接口（注册/登录/改密码） ----------------------
@app.post("/register", summary="用户注册（可指定角色）")
def register(user: UserCreate):
    conn = get_db()
    cursor = conn.cursor()
    # 检查用户名是否存在
    cursor.execute("SELECT id FROM user_accounts WHERE username=%s", (user.username,))
    if cursor.fetchone():
        raise HTTPException(400, "用户名已存在")

    try:
        # 插入用户（明文密码，内部测试用）
        cursor.execute(
            "INSERT INTO user_accounts (username, password, role) VALUES (%s,%s,%s)",
            (user.username, user.password, user.role)
        )
        uid = cursor.lastrowid

        # 初始化玩家数据
        init_weapons = json.dumps([])
        init_skills = json.dumps([])
        init_dressing = json.dumps({"HEAD": "", "BODY": "", "WEAPON": ""})
        cursor.execute("""
            INSERT INTO players (account_id, name, level, exp, gold, str, agi, spd, maxHp,
                win_count, lose_count, weapons, skills, dressing, role)
            VALUES (%s,%s,1,0,500,5,5,5,300,0,0,%s,%s,%s,%s)
        """, (uid, user.username, init_weapons, init_skills, init_dressing, user.role))

        conn.commit()
        return {"code": 200, "msg": f"注册成功！角色：{user.role}", "username": user.username}
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"注册失败：{str(e)}")
    finally:
        cursor.close()
        conn.close()

@app.post("/login", summary="用户登录")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """登录返回令牌+角色，用于后续权限判断"""
    conn = get_db()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute(
        "SELECT username, role FROM user_accounts WHERE username=%s AND password=%s",
        (form_data.username, form_data.password)
    )
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        raise HTTPException(401, "账号或密码错误")
    
    # 令牌中携带角色信息
    access_token = create_access_token(data={"sub": user["username"], "role": user["role"]})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"]
    }

@app.post("/change-password", summary="修改自己的密码")
def change_pwd(data: PasswordChange, current_user: Dict[str, Any] = Depends(get_current_user_info)):
    conn = get_db()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("SELECT password FROM user_accounts WHERE username=%s", (current_user["username"],))
    user = cursor.fetchone()
    
    if not user or user["password"] != data.old_password:
        raise HTTPException(400, "旧密码错误")

    cursor.execute(
        "UPDATE user_accounts SET password=%s WHERE username=%s",
        (data.new_password, current_user["username"])
    )
    conn.commit()
    cursor.close()
    conn.close()
    return {"code": 200, "msg": "密码修改成功"}

# ---------------------- 2. 普通玩家接口（仅改自己，分批/单字段） ----------------------
@app.get("/player/self", summary="查看自己的信息")
def get_self_info(current_user: Dict[str, Any] = Depends(get_current_user_info)):
    """普通玩家查看自己的完整数据"""
    username = current_user["username"]
    conn = get_db()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("""
        SELECT u.username, p.level, p.maxHp, p.gold, p.win_count, p.lose_count,
               p.weapons, p.skills, p.dressing
        FROM players p
        JOIN user_accounts u ON p.account_id = u.id
        WHERE u.username = %s
    """, (username,))
    player = cursor.fetchone()
    cursor.close()
    conn.close()

    if not player:
        raise HTTPException(404, "玩家信息不存在")
    
    # 解析JSON字段
    player["weapons"] = json.loads(player["weapons"]) if player["weapons"] else []
    player["skills"] = json.loads(player["skills"]) if player["skills"] else []
    player["dressing"] = json.loads(player["dressing"]) if player["dressing"] else {}
    return {"code": 200, "data": player}

@app.post("/player/self/update", summary="普通玩家修改自己的信息（分批）")
def update_self_info(data: PlayerSelfUpdate, current_user: Dict[str, Any] = Depends(get_current_user_info)):
    """普通玩家只能增量修改自己的属性，或覆盖武器/技能/装扮"""
    username = current_user["username"]
    pid = get_player_id(username)
    conn = get_db()
    cursor = conn.cursor()

    try:
        # 1. 增量修改数值属性（等级/血量/金币/胜负）
        update_sql = []
        update_params = []
        if data.add_level > 0:
            update_sql.append("level = level + %s")
            update_params.append(data.add_level)
            update_sql.append("maxHp = maxHp + %s")  # 升级同步加血量
            update_params.append(data.add_level * 50)
        if data.add_maxHp > 0:
            update_sql.append("maxHp = maxHp + %s")
            update_params.append(data.add_maxHp)
        if data.add_gold > 0:
            update_sql.append("gold = gold + %s")
            update_params.append(data.add_gold)
        if data.add_win > 0:
            update_sql.append("win_count = win_count + %s")
            update_params.append(data.add_win)
        if data.add_lose > 0:
            update_sql.append("lose_count = lose_count + %s")
            update_params.append(data.add_lose)
        
        # 2. 覆盖修改JSON属性（武器/技能/装扮）
        if data.weapons is not None:
            update_sql.append("weapons = %s")
            update_params.append(json.dumps(data.weapons))
        if data.skills is not None:
            update_sql.append("skills = %s")
            update_params.append(json.dumps(data.skills))
        if data.dressing is not None:
            update_sql.append("dressing = %s")
            update_params.append(json.dumps(data.dressing))
        
        # 执行更新
        if update_sql:
            sql = f"UPDATE players SET {', '.join(update_sql)} WHERE id = %s"
            update_params.append(pid)
            cursor.execute(sql, tuple(update_params))
            conn.commit()
        
        return {"code": 200, "msg": "个人信息修改成功"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"修改失败：{str(e)}")
    finally:
        cursor.close()
        conn.close()

# ---------------------- 3. 管理员专属接口（批量修改任意玩家） ----------------------
@app.get("/admin/players/all", summary="管理员查看所有玩家")
def admin_get_all_players(_=Depends(is_admin)):
    """管理员查看全服所有玩家完整数据"""
    conn = get_db()
    cursor = conn.cursor(pymysql.cursors.DictCursor)
    cursor.execute("""
        SELECT u.username, p.level, p.maxHp, p.gold, p.win_count, p.lose_count,
               p.weapons, p.skills, p.dressing
        FROM players p
        JOIN user_accounts u ON p.account_id = u.id
        ORDER BY p.level DESC, p.win_count DESC
    """)
    players = cursor.fetchall()
    cursor.close()
    conn.close()

    # 解析JSON字段
    for p in players:
        p["weapons"] = json.loads(p["weapons"]) if p["weapons"] else []
        p["skills"] = json.loads(p["skills"]) if p["skills"] else []
        p["dressing"] = json.loads(p["dressing"]) if p["dressing"] else {}
    return {"code": 200, "data": players}

@app.post("/admin/player/batch-update", summary="管理员批量修改任意玩家")
def admin_batch_update(data: AdminBatchUpdate, _=Depends(is_admin)):
    """管理员一次性修改目标玩家的所有属性（直接设置值，非增量）"""
    target_username = data.target_username
    pid = get_player_id(target_username)
    conn = get_db()
    cursor = conn.cursor()

    try:
        # 收集要修改的字段和值（仅修改非None的字段）
        update_sql = []
        update_params = []
        if data.level is not None:
            update_sql.append("level = %s")
            update_params.append(data.level)
        if data.maxHp is not None:
            update_sql.append("maxHp = %s")
            update_params.append(data.maxHp)
        if data.gold is not None:
            update_sql.append("gold = %s")
            update_params.append(data.gold)
        if data.win_count is not None:
            update_sql.append("win_count = %s")
            update_params.append(data.win_count)
        if data.lose_count is not None:
            update_sql.append("lose_count = %s")
            update_params.append(data.lose_count)
        if data.weapons is not None:
            update_sql.append("weapons = %s")
            update_params.append(json.dumps(data.weapons))
        if data.skills is not None:
            update_sql.append("skills = %s")
            update_params.append(json.dumps(data.skills))
        if data.dressing is not None:
            update_sql.append("dressing = %s")
            update_params.append(json.dumps(data.dressing))
        
        # 执行批量更新
        if update_sql:
            sql = f"UPDATE players SET {', '.join(update_sql)} WHERE id = %s"
            update_params.append(pid)
            cursor.execute(sql, tuple(update_params))
            conn.commit()
        
        return {"code": 200, "msg": f"玩家 {target_username} 数据批量修改成功"}
    except Exception as e:
        conn.rollback()
        raise HTTPException(500, f"批量修改失败：{str(e)}")
    finally:
        cursor.close()
        conn.close()

# ---------------------- 启动服务 ----------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)