require 'sinatra'
require 'data_mapper'
require 'sinatra/flash'
require 'pony'
require 'net/http'
require 'json'
require 'date'
require 'securerandom'
require 'digest/sha2'

configure :development do
  DataMapper::setup(:default, "sqlite3://#{Dir.pwd}/main.db")
end

configure :production do
  DataMapper.setup(:default, ENV['DATABASE_URL'])
end

class User
	include DataMapper::Resource
	property :id, Serial
  property :first_name, String, :default => ""
  property :last_name, String, :default => ""
	property :username, String
	property :password, Text
  property :email, String
  property :description, Text, :default => ""
  property :confirm_key, Text, :default => 0
  property :forgot_key, Text, :default => 0
  property :email_change_key, Text, :default => 0
  property :confirmed, Boolean, :default => 0
  property :major, String, :default => ""
  property :class_year, Integer, :default => Integer(Date.today.strftime("%Y"))
  property :schedule, String, :default => ""
  property :affiliation, String, :default => ""
  property :temp_new_email, String, :default => ""
  property :salt, Text, :default => ""
  property :is_admin, Boolean, :default => false
  property :lists, Text
  property :latestQuestionIndex, Integer, :default => 0
  property :surveyAnswers, Text, :default => ""
  property :groupings, Text, :default => ""
end

class Question
  include DataMapper::Resource
  property :id, Serial
  property :isRadio, Boolean
  property :question, String
  property :answers, String
end

DataMapper.auto_upgrade!

configure do
  enable :sessions
end

helpers do
  def protected!
    return if authorized?
    headers['WWW-Authenticate'] = 'Basic realm="Restricted Area"'
    halt 401, "Not authorized\n"
  end

  def authorized?
    @auth ||=  Rack::Auth::Basic::Request.new(request.env)
    @auth.provided? and @auth.basic? and @auth.credentials and @auth.credentials == ['admin', 'admin']
  end
end

def ensureLogin
  if not session.has_key?(:user)
    flash[:notice] = "Please log in first"
    redirect to '/'
  end
end

get '/answers' do
  u = User.get(session[:user])
  @questions = idToAnswers(u.surveyAnswers)
  if not @questions
    session[:error] = "You haven't answered any questions, go back to the <a href=\"http://localhost:9393/dashboard\">dashboard</a>"
  else
    session[:error] = ""
  end
  erb :answers
end

post '/answers' do
  q = Question.get(params[:qID])
  if params[("radio"+params[:qID]).to_sym]
    ans = params[("radio"+params[:qID]).to_sym].to_i
    u = User.get(session[:user])
    d = u.surveyAnswers.split(";")
    d2 = d[params[:qIndex].to_i].split(",")
    d2[1] = ans
    d[params[:qIndex].to_i] = d2.join(",")
    u.update(surveyAnswers: d.join(";"))
    flash[:notice] = "Answer changed successfully"
  end
  redirect to '/answers'
end

def idToAnswers(data)
  a = []
  data = data.split(";")
  for i in 0...data.length
    d = data[i].split(",")
    tempList = []
    q = Question.get(d[0])
    tempList.push(q.id)
    tempList.push(q.question)
    ans = q.answers.split("|")
    tempList.push(q.isRadio)
    tempList.push(ans)
    tempList.push(d[1])
    a.push(tempList)
  end
  return a
end

get '/groupings' do

end

get '/random' do
  ensureLogin
  @user = User.get(session[:user])
  # @other = getOtherRandomUser(@user)
  @other = getOtherRandomUser(@user)
  session[:other] = @other.id
  erb :random
end

post '/random' do
  user = User.get(session[:user])
  other = User.get(session[:other])
  send_message(user.email,
                 "DartmouthConnector Meal Confirmation",
                 "<h1>Hello #{user.first_name} #{user.last_name}</h1>"\
                 "You have a meal with the mysterious <a href=http://localhost:9393/profile/#{other.id}><b>#{other.first_name} #{other.last_name}</b></a>")
  send_message(other.email,
                 "DartmouthConnector Meal Confirmation",
                 "<h1>Hello #{other.first_name} #{other.last_name}</h1>"\
                 "You have a meal with the mysterious <a href=http://localhost:9393/profile/#{other.id}><b>#{user.first_name} #{user.last_name}</b></a>")
  flash[:notice] = "Email reminders with details sent"
  redirect '/dashboard'
end

def getOtherSimilarUser(user)

end

def getOtherRandomUser(user)
  i = User.first.id
  j = User.last.id
  return User.get(i+rand(j-i))
end

get '/profile' do
  ensureLogin
  redirect to "/profile/#{session[:user]}"
end

get '/profile/:id' do
  @user = User.get(params[:id])
  erb :profile
end

get '/admin' do
  protected!
  @users = User.all
  @questions = Question.all
  @question = ""
  @options = ""
  @isRadio = true
  if session[:question]
      @question = session[:question]
      session[:question] = nil
  end
  if session[:options]
      @options = session[:options]
      session[:options] = nil
  end

  if session[:qID]
    @id = session[:qID]
    @question = Question.get(session[:qID]).question
    @options = Question.get(session[:qID]).answers
    @isRadio = Question.get(session[:qID]).isRadio
    session[:qID] = nil
  end
  erb :admin
end

post '/admin' do
  protected!
  if params[:delete]
    Question.get(params[:num]).destroy
    flash[:notice] = "Question deleted"
  elsif params[:edit]
    session[:qID] = params[:num]
    session[:editon] = true
  else
    if session[:editon]
      q = Question.get(params[:qID])
      q.update(question: params[:question], answers: params[:options]);
      if params[:opt] == "radio"
        q.update(isRadio: true);
      else
        q.update(isRadio: false);
      end
      session[:editon] = nil
    else
      if params[:opt] == "radio"
        Question.create(isRadio: true, question: params[:question], answers: params[:options]).save
      elsif params[:opt] == "checkbox"
        Question.create(isRadio: false, question: params[:question], answers: params[:options]).save
      else
        flash[:notice] = "Select question type"
        session[:question] = params[:question]
        session[:options] = params[:options]
      end
    end
  end
  redirect to '/admin' 
end

# get '/makeadmin' do
#   User.get(session[:user]).update(is_admin: true)
# end

get '/create' do
  User.create(first_name: "Frank", last_name: "Sinatra",confirmed: true,email: "justintomejuan@gmail.com",username:"a",password:"").save
  User.create(first_name: "Jack", last_name: "Jones",confirmed: true,email: "justintomejuan@gmail.com",username:"b",password:"").save
  User.create(first_name: "Frank", last_name: "Buble",confirmed: true,email: "justintomejuan@gmail.com",username:"c",password:"").save
  User.create(first_name: "Paul", last_name: "McCartney",confirmed: true,email: "justintomejuan@gmail.com",username:"d",password:"").save
  User.create(first_name: "Harry", last_name: "Connick",confirmed: true,email: "justintomejuan@gmail.com",username:"d",password:"").save
  User.create(first_name: "Jinx", last_name: "Titanic",confirmed: true,email: "justintomejuan@gmail.com",username:"e",password:"").save
  User.create(first_name: "Mario", last_name: "Biondi",confirmed: true,email: "justintomejuan@gmail.com",username:"f",password:"").save
  User.create(first_name: "Andreas", last_name: "Weise",confirmed: true,email: "justintomejuan@gmail.com",username:"g",password:"").save
  User.create(first_name: "Patriozio", last_name: "Walker",confirmed: true,email: "justintomejuan@gmail.com",username:"h",password:"").save
  User.create(first_name: "Billy", last_name: "Joel",confirmed: true,email: "justintomejuan@gmail.com",username:"i",password:"").save
  # User.create(first_name: "Justin", last_name: "Chan",confirmed: true,email: "justintomejuan@gmail.com",username:"tomejuan",password:"123456",is_admin: true).save
  # User.create(first_name: "Justin", last_name: "Chan",confirmed: true,email: "justintomejuan@gmail.com",username:"tomejuan",password:"123456")
end

get '/clear' do
  User.all.each do |user|
    user.destroy
  end
end

get '/special' do
  User.get(session[:user]).update(surveyAnswers: "")
end

get '/creategroup' do
  ensureLogin
  @users = User.all
  erb :creategroup
end

post '/creategroup' do
  ensureLogin
  u = User.get(session[:user])
  u.update(lists: u.lists+namesToID(params[:hide])+";")
  session[:data] = namesToID(params[:hide])
  redirect to "/lists"
end

def namesToID(strings)
  l = strings.split(",")
  full_names=[]
  for string in l
    full_name=string[0...string.index("(")]
    full_names.push(full_name)
  end
  ids = []
  for full_name in full_names
    temp = full_name.split(" ")
    u = User.first(first_name: temp[0], last_name: temp[1])
    ids.push(u.id)
  end
  return ids.join(',')
end

get '/lists' do
  ensureLogin
  u = User.get(session[:user])
  temp = getListsAsArray
  if temp.length > 0
    @data = idsToNames(temp)
  else
    @error = "No lists created yet, create some <a href=\"/creategroup\">here</a>"
    @data = []
  end
  erb :lists
end

def idsToNames(ids)
  data = []
  for i in ids
    tempList = []
    for j in i
      tempList.push(User.get(j).first_name+" "+User.get(j).last_name)
    end
    data.push(tempList)
  end
  return data
end

post '/lists' do
  ensureLogin
  u = User.get(session[:user])
  l = getListsAsArray

  if params[:delete_list]
    l.delete_at(params[:listnum].to_i)
    u.update(lists: listArrayToString(l))
    @a = l
    redirect to '/lists'
  elsif params[:delete_people]
    session[:listnum] = params[:listnum].to_i
    full = getListsAsArray
    l = full[session[:listnum]]
    for i in (l.length-1).downto(0)
      if params[i.to_s.to_sym] == "on"
        l.delete_at(i)
      end
    end
    if l.length == 0
      full.delete_at(params[:listnum].to_i)
    end
    u.update(lists: listArrayToString(full))
    redirect to = '/lists'
  elsif params[:pair]
    session[:groupings] = nil
    session[:listnum] = params[:listnum].to_i
    if params[:n].to_i > 0
      session[:n] = params[:n].to_i
    else
      session[:n] = 2
      flash[:noice] = "Entry was invaild, try a number from 2 to the number of people in the list"
    end
    if session[:n] > l[session[:listnum]].length
      session[:n] = 2
      flash[:notice] = "Number entered was too big, defaulting to 2."
    end
    redirect to '/pair'
  else
    redirect to '/lists'
  end
end

get '/pair' do
  ensureLogin
  l = getListsAsArray
  @data=l[session[:listnum]]
  if session[:groupings]
    @a = idsToNames(session[:groupings])
  else
    temp = pairPeople(@data,session[:n])
    @a = idsToNames(temp)
    session[:groupings] = temp
  end
  
  erb :pair
end

post '/pair' do
  ensureLogin
  full = session[:groupings][params[:listnum].to_i]
  @temp = ""
  if params[:refresh]
    session[:groupings] = nil
    flash[:notice] = "Refreshed"
  elsif params[:email_all]
    for group in session[:groupings]
      for member in group
        user = User.get(member)
        listOfMembers = ""
        for member2 in group
          user2 = User.get(member2)
          if member2 != member
            listOfMembers += user2.first_name+" "+user2.last_name+", "
          end
        end
        listOfMembers=listOfMembers[0..listOfMembers.length-3]
        send_message(user.email,"DartmouthConnector Match Notification",
        "If you are not #{user.username} please ignore this email.<br/>"\
        "#{user.first_name} #{user.last_name} you have a group match meal with #{listOfMembers}.<br/>")

        flash[:notice] = @temp
      end
    end
  elsif params[:group]
      for member in full
        user = User.get(member)
        listOfMembers = ""
        for member2 in full
          user2 = User.get(member2)
          if member2 != member
            listOfMembers += user2.first_name+" "+user2.last_name+", "
          end
        end
        listOfMembers=listOfMembers[0..listOfMembers.length-3]
        send_message(user.email,"DartmouthConnector Match Notification",
        "If you are not #{user.username} please ignore this email.<br/>"\
        "#{user.first_name} #{user.last_name} you have a group match meal with #{listOfMembers}.<br/>")

        flash[:notice] = "Email reminders sent"
      end
  end
  @a = session[:groupings]
  redirect to '/pair'
end

def pairPeople(people,n)
  newList = []
  for i in 1...(people.length/2)
    tempList = []
    for j in 1..n
      num = rand(people.length-1)
      if people[num]
        tempList.push(people[num])
        people.delete_at(num)
      end
    end
    newList.push(tempList)
  end
  newList.push(people) if people.length > 0
  return newList
end

def pairPeopleRandom(people,n)
  newList = []
  for i in 1..people.length/2
    tempList = []
    for j in 1..rand(people.length)
      num = rand(newList.length-1)
      tempList.push(people[num])
      people.delete_at(num) 
    end
    if tempList.length > 0
      newList.push(tempList)
    end
  end
  newList.push(people)
  return newList
end

get '/forgot' do
  erb :forgot
end

post '/forgot' do
  if params[:email]
    if params[:email].end_with?("@dartmouth.edu")
      User.all.each do |user|
        if user.email == params[:email]
          key = getKey
          user.update(forgot_key: key)
          send_message(user.email,"DartmouthConnector Reset Password",
          "If you are not #{user.username} please ignore this email."\
          "Click <a href=\"http://localhost:9393/reset/#{user.id}/#{key}\">here</a> to reset password")
          flash[:notice] = "Reset message sent"
          redirect to '/login'
        end
      end
    end
  else
      flash[:notice] = "User with that email does not exist"
  end
  if params[:username]
    if params[:username].length > 6 and params[:username].length < 20
      User.all.each do |user|
        if user.username == params[:username]
          key = getKey
          user.update(forgot_key: key)
          send_message(user.email,"DartmouthConnector Reset Password",
          "If you are not #{user.username} please ignore this email."\
          "Click <a href=\"http://localhost:9393/reset/#{user.id}/#{key}\">here</a> to reset password")
          flash[:notice] = "Reset message sent"
          redirect to '/login'
        end
      end
    end
  else
      flash[:notice] = "User with that username does not exist"
  end
  redirect to :forgot
end

get '/reset/:id/:key' do
  @id = params[:id]
  @key = params[:key]
  user = User.get(params[:id])
  if not user
    session[:error] = "No such user exists"
  elsif params[:key] == 0 or user.forgot_key != params[:key]
    session[:error] = "Incorrect reset key, check your email and click on the link"
  else
    session[:error] = ""
  end

  erb :reset
end

post '/reset/:id/:key' do
  if params[:password]
    if params[:password].length < 6
      flash[:notice] = "Password must be at least 6 characters long"
      redirect to "/reset/#{params[:id]}/#{params[:key]}"
    elsif params[:password].length > 20
      flash[:notice] = "Password cannot be more than 20 characters long"
      redirect to "/reset/#{params[:id]}/#{params[:key]}"
    elsif params[:password] != params[:confirm_password]
      flash[:notice] = "Passwords do not match"
      redirect to "/reset/#{params[:id]}/#{params[:key]}"
    elsif session[:error] != ""
      redirect to "/reset/#{params[:id]}/#{params[:key]}"
    else 
      flash[:notice] = "Passwords changed successfully"
      User.get(params[:id]).update(password: params[:password])
      redirect to "/login"
    end
  end
end

get '/edit' do
  ensureLogin
  if not session.has_key?(:user)
    flash[:notice] = "Please log in first"
    redirect to '/'
  end
  @userObj = User.get(session[:user])
  @majors = ["African and Afro-American Studies","Anthropology","Art History","Asian and Middle Eastern Languages and Literatures","Asian and Middle Eastern Studies","Biological Sciences","Chemistry","Comparative Literature","Computer Science","Earth Science","Economics","Education","Engineering Sciences","English","Environmental Studies","Film and Television Studies","French and Italian","Geography","German","Government","History","Jewish Studies","Latin American, Latino, and Caribbean Studies","Linguistics and Cognitive Science","Mathematics","Music","Native American Studies","Philosophy","Physics and Astronomy","Psychological and Brain Sciences","Religion","Russian","Sociology","Spanish and Portuguese","Theater","Undecided","Women and Gender Studies"]
  @greeks = ["None","Alpha Chi Alpha","Alpha Delta","Alpha Phi","Alpha Phi Alpha","Alpha Pi Omega","Alpha Theta","Alpha Xi Delta","Beta","Bones Gate","Bones Gate","Chi Gamma Epsilon","Chi Heorot","Delta Delta Delta","Epsilon Kappa Theta","Gamma Delta Chi","Kappa Delta","Kappa Delta Epsilon","Kappa Kappa Gamma","Kappa Kappa Kappa","Lambda Upsilon Lambda","Phi Delta Alpha","Phi Tau","Psi Upsilon","Psi Upsilon","Sigma Alpha Epsilon","Sigma Delta","Sigma Lambda Upsilon","Sigma Nu","Sigma Phi Epsilon","The Tabard","Theta Delta Chi",]
  if not @greeks.include? @userObj.affiliation
    @greeks.push(@userObj.affiliation)
  end
  if not @majors.include? @userObj.major
    @majors.push(@userObj.major)
  end
  @start = Integer(Date.today.strftime("%Y"))-1
  @end = @start+4
  erb :edit
end

post '/edit' do
  ensureLogin
  user = User.get(session[:user])
  if params[:first_name].length > 30
    flash[:notice] = "First name must be less than 30 characters"
    redirect to '/edit'
  end
  if params[:last_name].length > 30
    flash[:notice] = "Last name must be less than 30 characters"
    redirect to '/edit'
  end
  if not params[:email].end_with?("@dartmouth.edu") or params[:email].end_with?("@alum.dartmouth.edu")
    flash[:notice] = "Email does not end with \"@dartmouth.edu\" or \"@alum.dartmouth.edu\""
    redirect to '/edit'
  end
  if params[:email] != user.email
    key = getKey
    user.update(email_change_key: key)
    user.update(temp_new_email: params[:email])
    flash[:notice] = "Sending confirmation email to #{params[:email]}"
    send_message(params[:email],
                 'DartmouthConnector Email Change Confirmation',
                 "<h1>Hello</h1>"\
                 "Click <a href=\"http://localhost:9393/emailchange/#{user.id}/#{key}\">here</a>")
    redirect to '/edit'
  end
  if params[:affiliation_other].length > 0
    user.update(affiliation: params[:affiliation_other])
  else
    user.update(affiliation: params[:affiliation])
  end
  if params[:major_other].length > 0
    user.update(major: params[:major_other])
  else
    user.update(major: params[:major])
  end

  user.update(first_name: params[:first_name])
  user.update(last_name: params[:last_name])
  user.update(class_year: params[:class_year])
  redirect to "/dashboard"
end

get '/emailchange/:id/:key' do
  ensureLogin
  userObj = User.get(params[:id])
  if not userObj
    flash[:notice] = "Account no longer exists"
    redirect '/'
  elsif userObj.email_change_key != params[:key]
    flash[:notice] = "Incorrect email change key"
    redirect '/' 
  end
  userObj.update(email: userObj.temp_new_email)
  userObj.update(temp_new_email: "")
  flash[:notice] = "Your email was changed successfully"
  redirect to :dashboard

  redirect to '/dashboard'
end

get '/confirm/:id/:num' do
  userObj = User.get(params[:id])
  if not userObj
    flash[:notice] = "Account no longer exists"
    redirect '/'
  elsif userObj.confirmed
    flash[:notice] = "Account has already been confirmed"
    redirect '/dashboard'
  elsif userObj.confirm_key != params[:num]
    flash[:notice] = "Incorrect confirmation key"
    redirect '/' 
  end
  userObj.update(confirmed: true)
  session[:user] = userObj.id
  flash[:notice] = "Your account has been confirmed"
  redirect to "/dashboard"
end

get '/dashboard' do
  ensureLogin
  @userObj = User.get(session[:user])
  
  if @userObj.latestQuestionIndex < Question.first.id or 
     @userObj.latestQuestionIndex > Question.last.id
    @userObj.update(latestQuestionIndex: Question.first.id)
  elsif not Question.get(@userObj.latestQuestionIndex) and @userObj.latestQuestionIndex < Question.last.id
    temp = @userObj.latestQuestionIndex
    while not Question.get(temp)
      temp += 1
    end
    @userObj.update(latestQuestionIndex: temp)
  end
  @q = Question.get(@userObj.latestQuestionIndex)

  erb :dashboard
end

post '/dashboard' do
  ensureLogin

  @userObj = User.get(session[:user])
  q = Question.get(@userObj.latestQuestionIndex)
  rep = ""
  rep += q.id.to_s+","
  if q.isRadio
    if params[:radio]
      rep += params[:radio]+","
      @userObj.update(surveyAnswers: @userObj.surveyAnswers+rep+";")
    else
      flash[:notice] = "Please select an answer"
      redirect to '/dashboard'
    end
  end
  @userObj.update(latestQuestionIndex: @userObj.latestQuestionIndex+1)

  redirect to '/dashboard'
end

get '/login' do
  erb :login
end

post '/login' do
  session[:username] = params[:username]
  if User.count(:username=>params[:username]) != 0
      user = User.first(username: params[:username])
      if not user.confirmed
        flash[:notice] = "Account has not yet been confirmed"
        redirect to "/login"
      end
      hashedPW = hashPassword(user.salt,params[:password].to_s).to_s
      if hashedPW == user.password
        session[:user] = user.id
        flash[:notice] = "Log in successful"
        redirect to "/dashboard"
      end
  end
  flash[:notice] = "Login details incorrect"
  redirect to "/login"
end

get '/logout' do
  if not session.has_key?(:user)
    flash[:notice] = "Please log in first"
    redirect to '/'
  end
  session.clear
  flash[:notice] = "Log out successful"
  redirect to '/'
end

get '/' do
  @title="Main"
	erb :main
end

get '/register' do
  @title="register"
  @username=session[:username]
  @email=session[:email]
  @success=session[:success]
	erb :register
end

post '/register' do
  session[:username] = params[:username]
  session[:email] = params[:email]

  res = Net::HTTP.post_form(
    URI.parse('http://www.google.com/recaptcha/api/verify'),
    {
      'privatekey' => '6Ldn9O0SAAAAAHfRP5jqm0kMGoAVdVy4B3B7UVhI',
      'remoteip'   => request.ip,
      'challenge'  => params[:recaptcha_challenge_field],
      'response'   => params[:recaptcha_response_field]
    }
  )
  success, error_key = res.body.lines.map(&:chomp)

  if User.count(:username=>params[:username]) > 0
      user = User.first(:username=>params[:username])
      if not user.confirmed
        flash[:notice] = "Please confirm your account"
      else
        flash[:notice] = "Account with that username already exists"
      end
  elsif User.count(:email=>params[:email]) > 0
    user = User.first(:email=>params[:email])
    if not user.confirmed
      flash[:notice] = "Please confirm your account"
    else
      flash[:notice] = "Account with that email already exists"
    end
  elsif success == 'false'
    flash[:notice] = "Captcha incorrectly entered"
  elsif params[:username].length < 6
    flash[:notice] = "Username must be at least 6 characters long"
  elsif params[:username].length > 20
    flash[:notice] = "Username cannot be more than 20 characters long"
  elsif params[:password].length < 6
    flash[:notice] = "Password must be at least 6 characters long"
  elsif params[:password].length > 20
    flash[:notice] = "Password cannot be more than 20 characters long"
  elsif params[:password] != params[:confirm_password]
    flash[:notice] = "Your passwords do not match"
  elsif not params[:email].end_with? "@dartmouth.edu" or params[:email].end_with? "@alum.dartmouth.edu"
  	flash[:notice] = "Please enter an email address that ends with \"@dartmouth.edu\" or \"@alum.dartmouth.edu\""
  else 
    flash[:notice] = "Thanks for registering, we will send an email shortly"
    key = getKey
    salt = getKey
    hashedPW = hashPassword(salt,params[:password].to_s).to_s
    h=User.create(username: params[:username], password: hashedPW, 
                email: params[:email], confirm_key: key, salt: salt).save
    id = User.last.id
    # session[:user] = id
    send_message(params[:email],
                 "DartmouthConnector Confirmation Email",
                 "<h1>Hello</h1>"\
                 "Click <a href=\"http://localhost:9393/confirm/#{id}/#{key}\">here</a>")
    session.clear
    redirect to "/login"
  end
  redirect to "/register"
end

def send_message(address,subject,message)
  Pony.mail   :to => address,
              :from => 'Justin Chan',
              :subject => subject,
              # :headers => { 'Content-Type' => 'text/html' },
              :html_body => message
              # :via => :smtp,
              # :via_options => {
              #   :host => "smtp.gmail.com",
              #   :port => 465,
              #   :user_name => "dartmouth.connector@gmail.com",
              #   :password => 'frankie42',
              #   :tls => true } 
end

def getListsAsArray
  a = User.get(session[:user]).lists
  if a
    l=[]
    temp = a.split(";")
    for i in temp
      l.push(i.split(","))
    end
    return l
  end
end

def listArrayToString(a)
  str = ""
  a.each do |list|
    list.each do |person|
      str += person+","
    end
    str += ";"
  end
  return str
end

def hashPassword(salt,password)
  for i in 1..1000
    h = Digest::SHA2.new(256) << salt+password
  end
  return h
end

def getKey
  return SecureRandom.urlsafe_base64(40)
end
