from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import requests
import json
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chat.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API密钥
API_KEY = "sk-ribiwlexfwvdfawkvxkvyauijnoscgxcxpepiazmwxlrnqcd"

# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    conversations = db.relationship('Conversation', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# 对话模型
class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    messages = db.relationship('Message', backref='conversation', lazy=True, cascade='all, delete-orphan')

# 消息模型
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'), nullable=False)
    is_bot = db.Column(db.Boolean, default=False)
    reasoning_content = db.Column(db.Text, nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('邮箱已被注册')
            return redirect(url_for('register'))
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('注册成功！请登录')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('chat'))
        
        flash('用户名或密码错误')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/chat')
@login_required
def chat():
    # 获取当前对话ID
    conversation_id = request.args.get('conversation_id', type=int)
    
    # 获取用户的所有对话
    conversations = Conversation.query.filter_by(user_id=current_user.id).order_by(Conversation.updated_at.desc()).all()
    
    # 如果没有指定对话ID且用户有对话记录，使用最新的对话
    if not conversation_id and conversations:
        conversation_id = conversations[0].id
    
    # 获取当前对话的消息
    messages = []
    current_conversation = None
    if conversation_id:
        current_conversation = Conversation.query.get_or_404(conversation_id)
        if current_conversation.user_id != current_user.id:
            return redirect(url_for('chat'))
        messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp.asc()).all()
    
    return render_template('chat.html', 
                         messages=messages, 
                         conversations=conversations,
                         current_conversation=current_conversation)

@app.route('/new_chat')
@login_required
def new_chat():
    # 创建新对话，使用默认标题
    conversation = Conversation(
        user_id=current_user.id, 
        title="新对话",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    db.session.add(conversation)
    db.session.commit()
    
    # 重定向到新对话
    return redirect(url_for('chat', conversation_id=conversation.id))

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.json.get('message')
    conversation_id = request.json.get('conversation_id')
    
    if not content:
        return jsonify({'error': '消息不能为空'}), 400
    
    # 如果没有指定对话ID，创建新对话
    if not conversation_id:
        conversation = Conversation(user_id=current_user.id, title=content[:50])
        db.session.add(conversation)
        db.session.commit()
        conversation_id = conversation.id
    else:
        conversation = Conversation.query.get_or_404(conversation_id)
        if conversation.user_id != current_user.id:
            return jsonify({'error': '无权访问此对话'}), 403
    
    # 保存用户消息
    user_message = Message(
        content=content, 
        user_id=current_user.id, 
        conversation_id=conversation_id,
        is_bot=False
    )
    db.session.add(user_message)
    
    # 更新对话标题（如果是第一条消息）
    if not conversation.title or conversation.title == "新对话":
        conversation.title = content[:50]
    
    # 更新对话时间
    conversation.updated_at = datetime.utcnow()
    db.session.commit()

    try:
        # 获取历史消息
        history_messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp.asc()).limit(10).all()
        
        # 调用真实API获取回答
        logger.info(f"调用SiliconFlow API，消息内容: {content[:30]}...")
        bot_response, reasoning_content = call_siliconflow_api(content, history_messages)
        
        # 保存机器人回复
        bot_message = Message(
            content=bot_response,
            user_id=current_user.id,
            conversation_id=conversation_id,
            is_bot=True,
            reasoning_content=reasoning_content
        )
        db.session.add(bot_message)
        db.session.commit()
        
        logger.info("成功获取API回复")
        return jsonify({
            'conversation_id': conversation_id,
            'user_message': {
                'content': content,
                'timestamp': user_message.timestamp.isoformat()
            },
            'bot_message': {
                'content': bot_response,
                'timestamp': bot_message.timestamp.isoformat(),
                'reasoning_content': reasoning_content
            }
        })
        
    except Exception as e:
        logger.error(f"API调用失败: {str(e)}")
        return jsonify({'error': f'发送消息失败: API调用错误: {str(e)}'}), 500

@app.route('/update_conversation_title', methods=['POST'])
@login_required
def update_conversation_title():
    conversation_id = request.json.get('conversation_id')
    new_title = request.json.get('title')
    
    if not conversation_id or not new_title:
        return jsonify({'error': '参数错误'}), 400
        
    conversation = Conversation.query.get_or_404(conversation_id)
    if conversation.user_id != current_user.id:
        return jsonify({'error': '无权修改此对话'}), 403
        
    conversation.title = new_title
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/delete_conversation/<int:conversation_id>', methods=['POST'])
@login_required
def delete_conversation(conversation_id):
    conversation = Conversation.query.get_or_404(conversation_id)
    if conversation.user_id != current_user.id:
        return jsonify({'error': '无权删除此对话'}), 403
        
    db.session.delete(conversation)
    db.session.commit()
    
    return jsonify({'success': True})

# 调用SiliconFlow API
def call_siliconflow_api(content, history_messages=None):
    """调用SiliconFlow API获取回答"""
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json"
    }
    
    api_url = "https://api.siliconflow.cn/v1/chat/completions"
    
    # 构建消息历史
    messages = [
        {
            "role": "system",
            "content": "你是安庆师范大学的AI助手，你的任务是帮助师生解答问题。请用专业、友善的态度回答问题。"
        }
    ]
    
    # 添加历史消息（只使用当前对话的历史）
    if history_messages:
        # 限制历史消息数量，只保留最近的10条
        recent_messages = history_messages[-10:]
        for msg in recent_messages:
            role = "assistant" if msg.is_bot else "user"
            messages.append({"role": role, "content": msg.content})
    
    # 添加当前用户消息
    messages.append({"role": "user", "content": content})
    
    # 构建请求数据，按照API文档格式
    data = {
        "model": "deepseek-ai/DeepSeek-R1",  # 使用免费版本的模型
        "messages": messages,
        "stream": False,
        "max_tokens": 2048,
        "temperature": 0.7,
        "top_p": 0.7,
        "top_k": 50,
        "frequency_penalty": 0.5,
        "n": 1,
        "response_format": {
            "type": "text"
        }
    }
    
    logger.info(f"发送API请求到: {api_url}")
    logger.info(f"请求数据: {json.dumps(data)}")
    
    try:
        # 禁用代理配置，直接连接
        proxies = {
            "http": None,
            "https": None,
        }
        
        response = requests.post(
            api_url,
            headers=headers,
            json=data,
            timeout=60,
            proxies=proxies,
            verify=True  # 确保SSL验证开启
        )
        
        logger.info(f"API响应状态码: {response.status_code}")
        
        if response.status_code == 200:
            response_data = response.json()
            logger.info(f"API响应: {json.dumps(response_data)[:100]}...")
            
            # 解析返回的消息内容
            if 'choices' in response_data and len(response_data['choices']) > 0:
                # 获取模型回复内容
                message_content = response_data['choices'][0]['message']['content']
                
                # 获取推理内容
                reasoning_content = None
                if 'reasoning_content' in response_data['choices'][0]['message']:
                    reasoning_content = response_data['choices'][0]['message']['reasoning_content']
                    logger.info(f"模型推理过程: {reasoning_content[:100]}...")
                
                return message_content, reasoning_content
            else:
                raise Exception("API响应格式错误，找不到回复内容")
        elif response.status_code == 403:
            error_data = response.json()
            if error_data.get('code') == 30011:
                raise Exception("模型余额不足，请充值后重试")
            else:
                raise Exception(f"API授权错误: {error_data.get('message', '未知错误')}")
        else:
            error_msg = f"API返回错误: HTTP {response.status_code}, {response.text}"
            logger.error(error_msg)
            raise Exception(error_msg)
            
    except requests.exceptions.RequestException as e:
        logger.error(f"API请求异常: {str(e)}")
        raise Exception(f"API请求失败: {str(e)}")
    except json.JSONDecodeError as e:
        logger.error(f"API响应JSON解析错误: {str(e)}")
        raise Exception(f"API响应格式错误: {str(e)}")
    except Exception as e:
        logger.error(f"API调用未知错误: {str(e)}")
        raise Exception(f"API调用失败: {str(e)}")

@app.context_processor
def utility_processor():
    return dict(now=datetime.now)

if __name__ == '__main__':
    with app.app_context():
        # 删除所有表并重新创建
        db.drop_all()
        db.create_all()
        
        # 创建测试用户（可选）
        test_user = User.query.filter_by(username='test').first()
        if not test_user:
            test_user = User(username='test', email='test@example.com')
            test_user.set_password('test')
            db.session.add(test_user)
            db.session.commit()
            
    app.run(debug=True) 