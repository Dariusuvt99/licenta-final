from flask import *
import sqlite3, hashlib, os, datetime, random
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'random string'
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = set(['jpeg', 'jpg', 'png', 'gif', 'webp'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def getLoginDetails():
    isAdmin = False
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        if 'email' not in session:
            loggedIn = False
            fName = ''
            itemsNo = 0
            userId = 0
        else:
            loggedIn = True
            crs.execute('SELECT userId, fName FROM users WHERE email = ?', (session['email'], ))
            userId, fName = crs.fetchone()
            crs.execute('SELECT count(prodId) FROM cart WHERE userId = ?', (userId, ))
            itemsNo = crs.fetchone()[0]
            crs.execute('SELECT role from users_roles WHERE userId = ?', (userId, ))
            role = crs.fetchone()
            if role:
                isAdmin = (role[0] == 'admin')
            
    cnn.close()
    return (loggedIn, fName, itemsNo, userId, isAdmin)

def get_user_details(email):
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute('''SELECT 
                    fName, lName, addr1, addr2, zip, city, county, country, mobile 
                    FROM users 
                    WHERE email = ?''', (email, ))
        return crs.fetchone()
    
"""
Generates the SQL select clause for a group of filters
    - inside a filter group there is an OR (ie. men OR kids)
    - between filter groups is AND (i.e. men AND shoes)
"""
def compile_filter_clause(filters):
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute("select filterId, name from filter")
        filterGroups = crs.fetchall()  
        
        crs.execute("select categId, name, filterId from categs")
        categs = crs.fetchall()    
        
        andFilter = []
        for g in filterGroups:
            orFilter = []  
            for c in categs:
                if (c[0] in filters) and (c[2] == g[0]):
                    orFilter.append(" (catId = " + str(c[0]) + ") ")
            if orFilter:
                andFilter.append(" select distinct(prodId) from prodcat where (" + " OR ".join(orFilter) + ")")
            
        return " INTERSECT ".join(andFilter)
  
    
"""
Render the main page, including also the header, footer and the filters and search query
"""
def render_main_page(searchQuery = None, filters=[], instock = False):
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        
        orderClause = " order by random() "
        filterClauses = []
        if filters:
            fc = compile_filter_clause(filters)
            filterClauses.append(" (prodId in (" + fc + " ))")
            
        if instock:
            filterClauses.append(' stock > 0 ')
         
        filterClause = " AND ".join(filterClauses)
            
        
        baseSelect = '''SELECT 
                            prodId as prodId, name, price, descr, img, stock
                        FROM prods
                        '''
        if (searchQuery):
            if (filterClause):
                filterClause = ' AND ' + filterClause
            searchQueryWild = '%' + searchQuery + '%'
            crs.execute(baseSelect 
                        + ' WHERE (name LIKE ? or descr LIKE ?) '
                        + filterClause + orderClause, (searchQueryWild, searchQueryWild,))
        else:
            if (filterClause):
                filterClause = ' WHERE ' + filterClause
            crs.execute(baseSelect + filterClause + orderClause)
        itemData = crs.fetchall()
        
        nrinstock = 0
        for item in itemData:
            if item[5] > 0:
                nrinstock += 1
        
        crs.execute('SELECT categId, name FROM categs')
        categoryData = crs.fetchall()
        
        crs.execute('SELECT * FROM filter')
        filterData = crs.fetchall()
                
        baseFilterSelect = '''SELECT 
                    prodcat.catId,	
                    count(prodcat.catId) as nr, 
                    categs.name as category, 
                    filter.filterId, 
                    filter.name as filter 
                    FROM prods 
                    left JOIN prodcat on prods.prodId = prodcat.prodId
                    LEFT JOIN categs on prodcat.catId = categs.categId 
                    LEFT JOIN filter on categs.filterId = filter.filterId '''
        filtersGroup = ' group by prodcat.catId'
        if (searchQuery):
            searchQueryWild = '%' + searchQuery + '%'
            crs.execute(baseFilterSelect 
                        + ' WHERE prods.name LIKE ? or prods.descr LIKE ? ' 
                        + filtersGroup ,
                        (searchQueryWild, searchQueryWild,))
        else:
            crs.execute(baseFilterSelect + filtersGroup)
 
        filterGroup = crs.fetchall()
        filterGroupSelected = []
        
        for filter in filterGroup:
            selected = filter[0] in filters
            filterGroupSelected.append( (filter[0], filter[1], filter[2], filter[3], selected) )
        
    return render_template('home.html', itemData=itemData, searchQuery=searchQuery, filters=filters, filterGroup=filterGroupSelected, filterData=filterData, instock=instock, nrinstock=nrinstock, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, categoryData=categoryData, isAdmin=isAdmin)

    
@app.route("/")
def root():
    return render_main_page()
   
@app.route('/search', methods = ['POST'])
def search_items():
    searchQuery = request.form['searchQuery']
    if 'instock' in request.form:
        instock = request.form['instock']
    else:
        instock = False
    
    filters = []
    for item in request.form:
        if item.startswith('categ'):
            catId = (int)(item.replace('categ-',''))
            filters.append(catId)
            
    return render_main_page(searchQuery, filters, instock)
  
@app.route("/add")
def addProduct():
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute('SELECT categId, name FROM categs')
        categs = crs.fetchall()
        
        crs.execute('SELECT categId, name, filterId FROM categs')
        categoryData = crs.fetchall()
        
        crs.execute('select filterId, name from filter')
        filters = crs.fetchall()

        # populate selected/not selected as new array
        fullCategoryData = []
        for cat in categoryData:
            if cat:
                # save selection data (tuples are imutable)
                fullCategoryData.append ( ( cat[0], 
                                            cat[1],
                                            False,
                                            cat[2]) )
            
        return render_template('add.html', categoryData=fullCategoryData, filters=filters, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)

    cnn.close()
    return render_template('add.html', categs=categs, categoryData=categoryData)


@app.route("/saveItem", methods=["POST"])
def saveItem():
    try:
        if 'prodId' in request.form:
            id = request.form['prodId']
        else:
            id = None
        name = request.form['name']
        price = float(request.form['price'])
        descr = request.form['descr']
        stock = int(request.form['stock'])
        #categId = int(request.form['categ'])
        img = request.files['img']
        imagename = None
        if img and allowed_file(img.filename):
            filename = secure_filename(img.filename)
            img.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            imagename = filename
            
        selecteCategories = []
        for item in request.form:
            if item.startswith("categ"):
                catId = (int)(item.replace("categ-",""))
                selecteCategories.append(catId)
            
        with sqlite3.connect('database.db') as cnn:
            try:
                crs = cnn.cursor()
                if id:
                    crs.execute('''UPDATE prods SET
                                name=?, 
                                price=?, 
                                descr=?, 
                                stock=? 
                                WHERE prodId=? ''', (name, price, descr, stock, id))
                    
                    if imagename:
                        crs.execute('UPDATE prods SET img=? where prodId=?', imagename, id)
                        
                    cnn.commit()
                    mess="Updated successfully"
                else:
                    crs.execute('''INSERT INTO prods 
                                    (name, price, descr, img, stock) 
                                    VALUES (?, ?, ?, ?, ?) ''', 
                                (name, price, descr, imagename, stock))
                    cnn.commit()
                    id = crs.lastrowid
                    mess="Added successfully"
                
                print ("product id", id)
                crs.execute("delete from prodcat where prodId=?", (id,))
                for catId in selecteCategories:
                    crs.execute("insert into prodcat (prodId, catId) VALUES (?,?)", (id, catId))
                cnn.commit()
            except Exception as e:
                print(e)
                mess="Error occured: " + str(e)
                cnn.rollback()
        cnn.close()
        print(mess)
        return redirect(url_for('root'))
    except Exception as e:
           return render_template("errorMessage.html", title="Error occured", message=e)
     
    
    
@app.route("/edit", methods=["GET"])
def edit():
    prodId = request.args.get("prodId")
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        
        crs.execute('SELECT categId, name, filterId FROM categs')
        categoryData = crs.fetchall()
        
        crs.execute('select * from prods where prodId=?', (prodId,))
        prod = crs.fetchall()
        
        crs.execute('select catId from prodcat where prodId=?', (prodId,))
        cats = crs.fetchall()
        
        crs.execute('select filterId, name from filter')
        filters = crs.fetchall()
        
        selectedCategories = []
        for cat in cats:
            selectedCategories.append(cat[0])
         
        # populate selected/not selected as new array
        fullCategoryData = []
        for cat in categoryData:
            if cat:
                selected = cat[0] in selectedCategories
                # save selection data (tuples are imutable)
                fullCategoryData.append ( ( cat[0], 
                                            cat[1],
                                            selected,
                                            cat[2]) )
            
        return render_template('edit.html', prod=prod[0], categoryData=fullCategoryData, filters=filters, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)

@app.route("/remove")
def remove():
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute('SELECT prodId, name, price, descr, img, stock FROM prods')
        data = crs.fetchall()
    cnn.close()
    return render_template('remove.html', data=data)

@app.route("/removeItem")
def removeItem():
    prodId = request.args.get('prodId')
    with sqlite3.connect('database.db') as cnn:
        try:
            crs = cnn.cursor()
            crs.execute('DELETE FROM prods WHERE prodID = ?', (prodId, ))
            cnn.commit()
            mess = "Deleted successsfully"
        except:
            cnn.rollback()
            mess = "Error occured"
    cnn.close()
    print(mess)
    return redirect(url_for('root'))

@app.route("/displayCategory")
def displayCategory():
        loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
        categId = request.args.get("categId")
        with sqlite3.connect('database.db') as cnn:
            crs = cnn.cursor()
            crs.execute('SELECT prods.prodId, prods.name, prods.price, prods.img, categs.name FROM prods, categs WHERE prods.categId = categs.categId AND categs.categId = ?', (categId, ))
            data = crs.fetchall()
        cnn.close()
        categoryName = data[0][4]
        data = parse(data)
        return render_template('displayCategory.html', data=data, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, categoryName=categoryName, isAdmin=isAdmin)

@app.route("/account/profile")
def profileHome():
    if 'email' not in session:
        return redirect(url_for('root'))
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    return render_template("profileHome.html", loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)


@app.route("/account/orders")
def profileOrders():
    if 'email' not in session:
        return redirect(url_for('root'))
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute('select * from orders where userId=? order by orderId desc', (userId,))
        orders = crs.fetchall()
    return render_template("orders.html", orders=orders, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)


@app.route("/account/profile/edit")
def editProfile():
    if 'email' not in session:
        return redirect(url_for('root'))
    loggedIn, fName, itemsNo, userI, isAdmin = getLoginDetails()
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute("SELECT userId, email, fName, lName, addr1, addr2, zip, city, county, country, mobile FROM users WHERE email = ?", (session['email'], ))
        profileData = crs.fetchone()
    cnn.close()
    return render_template("editProfile.html", profileData=profileData, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)

@app.route("/account/profile/changePassword", methods=["GET", "POST"])
def changePassword():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    if request.method == "POST":
        oldPassword = request.form['oldpassword']
        oldPassword = hashlib.md5(oldPassword.encode()).hexdigest()
        newPassword = request.form['newpassword']
        newPassword = hashlib.md5(newPassword.encode()).hexdigest()
        with sqlite3.connect('database.db') as cnn:
            crs = cnn.cursor()
            crs.execute("SELECT userId, password FROM users WHERE email = ?", (session['email'], ))
            userId, password = crs.fetchone()
            if (password == oldPassword):
                try:
                    crs.execute("UPDATE users SET password = ? WHERE userId = ?", (newPassword, userId))
                    cnn.commit()
                    mess="Changed successfully"
                except:
                    cnn.rollback()
                    mess = "Failed"
                return render_template("changePassword.html", mess=mess)
            else:
                mess = "Wrong password"
        cnn.close()
        return render_template("changePassword.html", mess=mess)
    else:
        return render_template("changePassword.html")

@app.route("/updateProfile", methods=["GET", "POST"])
def updateProfile():
    if request.method == 'POST':
        email = request.form['email']
        fName = request.form['fName']
        lName = request.form['lName']
        addr1 = request.form['addr1']
        addr2 = request.form['addr2']
        zip = request.form['zip']
        city = request.form['city']
        county = request.form['county']
        country = request.form['country']
        mobile = request.form['mobile']
        password = request.form['password']
        with sqlite3.connect('database.db') as conn:
                try:
                    crs = conn.cursor()
                    crs.execute('UPDATE users SET fName = ?, lName = ?, addr1 = ?, addr2 = ?, zip = ?, city = ?, county = ?, country = ?, mobile = ? WHERE email = ?', (fName, lName, addr1, addr2, zip, city, county, country, mobile, email))

                    conn.commit()
                    mess = "Saved Successfully"
                    
                    if password:
                        crs.execute('update users set password = ? where email = ?',
                                    (hashlib.md5(password.encode()).hexdigest(), email))
                except:
                    conn.rollback()
                    mess = "Error occured"
        conn.close()
        return redirect(url_for('root'))

@app.route("/loginForm")
def loginForm():
    if 'email' in session:
        return redirect(url_for('root'))
    else:
        return render_template('login.html', error='')

@app.route("/login", methods = ['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        if is_valid(email, password):
            session['email'] = email
            return redirect(url_for('root'))
        else:
            error = 'Invalid UserId / Password'
            return render_template('login.html', error=error)

def get_similar_products(tags):
    similar = []
    
    categIds = []
    for t in tags:
        categIds.append( t[1] )
 
    ids = ','.join(map(str, categIds))
   
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute(''' select prodId, name, img 
                        from prods
                        where prodId in (
                            select 
                            distinct(prodId) 
                                from 
                                    prodcat 
                                where 
                                    prodcat.catId in ( ''' + ids + ''' )
                        )
                        ORDER BY RANDOM() 
                        limit 10;
                        ''')
        similar = crs.fetchall()
        random.shuffle(similar)

    return similar
    
@app.route("/productDescription")
def productDescription():
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    prodId = request.args.get('prodId')
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute('SELECT prodId, name, price, descr, img, stock FROM prods WHERE prodId = ?', (prodId, ))
        productData = crs.fetchone()
        
        crs.execute(''' select 
                            idValue, name
                        from size_values 
                        WHERE idGroup in (
                            select 
                                idGroup 
                            from size_cats 
                            where size_cats.idCat in (
                                select prodcat.catId
                                from prodcat where prodcat.prodId = ? 
                            )
                        )
                    ''', (prodId, ))
        sizes = crs.fetchall()
        
        crs.execute('''select 
                            categs.name, categs.categId
                        from prodcat
                        LEFT JOIN categs on prodcat.catId = categs.categId
                        where prodId=? ''', (prodId, ))
        tags = crs.fetchall()
        
        similar = get_similar_products(tags)
    cnn.close()
    return render_template("productDescription.html", data=productData, sizes=sizes, tags=tags, similar=similar, loggedIn = loggedIn, fName = fName, itemsNo = itemsNo, isAdmin=isAdmin)

@app.route("/addToCart", methods = ['POST'])
def addToCart():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    else:
        prodId = int(request.form['prodId'])
        qty = int(request.form['qty'])
        sizeId = int(request.form['sizeId'])
        
        with sqlite3.connect('database.db') as cnn:
            crs = cnn.cursor()
            crs.execute("SELECT userId FROM users WHERE email = ?", (session['email'], ))
            userId = crs.fetchone()[0]
            try:
                crs.execute("INSERT INTO cart (userId, prodId, sizeId, qty) VALUES (?, ?, ?, ?)", (userId, prodId, sizeId, qty))
                cnn.commit()
                mess = "Added successfully"
            except:
                cnn.rollback()
                mess = "Error occured"
        cnn.close()
        return redirect(url_for('root'))

def get_cart_products(userId):
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute(''' SELECT 
                        prods.prodId, prods.name, prods.price, prods.img, 
                        cart.qty, 
                        cart.sizeId,
                        size_values.name as size
                    FROM prods, cart 
                        left join size_values on cart.sizeId = size_values.idValue
                    WHERE 
                        prods.prodId = cart.prodId AND cart.userId = ?
                    ''', (userId, ))
        prods = crs.fetchall()
    totalPrice = 0
    for row in prods:
        totalPrice += row[2]
    return prods, totalPrice
        
@app.route("/cart")
def cart():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    prods, totalPrice = get_cart_products(userId)
    
    return render_template("cart.html", products=prods, totalPrice=totalPrice, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)

@app.route("/checkout")
def checkout():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    email = session['email']
    prods, totalPrice = get_cart_products(userId)
    user = get_user_details(email)
    return render_template("checkout.html", products=prods, totalPrice=totalPrice, user=user, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)

def decrease_stock(prods):
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        for p in prods:
            crs.execute("update prods set stock = stock - 1 where prodId = ?", (p[0], ))    
    
def create_new_order(userId, totalPrice):
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        crs.execute('''insert into orders 
                        (userId, dateTime, totalPrice) 
                        values (?,?,?)''', (userId, now, totalPrice))
        return crs.lastrowid
   
def add_prods_to_order(orderId, prods):
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        for p in prods:
            crs.execute('''insert into order_prods
                        (orderId, prodId, sizeId, qty, price)
                        values (?,?,?,?,?)
                        ''', (orderId, p[0], p[5], p[4], p[2]))
         
def clean_cart(userId):
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute('delete from cart where userId = ?', (userId,))
        
@app.route("/order")
def order():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    prods, totalPrice = get_cart_products(userId)
    
    orderId = create_new_order(userId, totalPrice)
    add_prods_to_order(orderId, prods)
    decrease_stock(prods)
    clean_cart(userId)
    
    return render_template("confirmation.html", orderId=orderId, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)


@app.route("/removeFromCart")
def removeFromCart():
    if 'email' not in session:
        return redirect(url_for('loginForm'))
    email = session['email']
    prodId = int(request.args.get('prodId'))
    sizeId = int(request.args.get('sizeId'))
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute("SELECT userId FROM users WHERE email = ?", (email, ))
        userId = crs.fetchone()[0]
        try:
            crs.execute("DELETE FROM cart WHERE userId = ? AND prodId = ? AND sizeId = ?", (userId, prodId, sizeId))
            cnn.commit()
            mess = "removed successfully"
        except:
            cnn.rollback()
            mess = "error occured"
    cnn.close()
    return redirect(url_for('cart'))

@app.route("/logout")
def logout():
    session.pop('email', None)
    return redirect(url_for('root'))

def is_valid(email, password):
    conn = sqlite3.connect('database.db')
    crs = conn.cursor()
    crs.execute('SELECT email, password FROM users')
    data = crs.fetchall()
    for row in data:
        if row[0] == email and row[1] == hashlib.md5(password.encode()).hexdigest():
            return True
    return False

@app.route("/register", methods = ['GET', 'POST'])
def register():
    if request.method == 'POST':

        password = request.form['password']
        email = request.form['email']
        fName = request.form['fName']
        lName = request.form['lName']
        addr1 = request.form['addr1']
        addr2 = request.form['addr2']
        zip = request.form['zip']
        city = request.form['city']
        county = request.form['county']
        country = request.form['country']
        mobile = request.form['mobile']

        with sqlite3.connect('database.db') as conn:
            try:
                crs = conn.cursor()
                crs.execute('INSERT INTO users (password, email, fName, lName, addr1, addr2, zip, city, county, country, mobile) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', (hashlib.md5(password.encode()).hexdigest(), email, fName, lName, addr1, addr2, zip, city, county, country, mobile))

                conn.commit()

                mess = "Registered Successfully"
            except:
                conn.rollback()
                mess = "Error occured"
        conn.close()
        return render_template("login.html", error=mess)

@app.route("/registerationForm")
def registrationForm():
    return render_template("register.html")

@app.route("/admin", methods=["GET"])
def admin():
    prodId = request.args.get("prodId")
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    if isAdmin:
        with sqlite3.connect('database.db') as cnn:
            crs = cnn.cursor()
        
            crs.execute('''SELECT 
                            prodId as prodId, name, price, descr, img, stock
                        FROM prods''')
            products = crs.fetchall()
            
            crs.execute('''SELECT 
                            orderId, dateTime, totalPrice, fName, lName
                        FROM orders 
                        LEFT JOIN users ON
                            orders.userId = users.userId 
                        order by dateTime desc ''')
            orders = crs.fetchall()
            
            crs.execute('''SELECT userId, email, fName, lName from users''')
            users = crs.fetchall()

            return render_template("admin.html", products=products, orders=orders, users=users, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)
        
    else:
        return render_template("errorMessage.html", title="Not allowed", message="You dont' have the right to access this page!",  loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)
        
        

@app.route("/viewOrder")
def viewOrder():
    orderId = int(request.args.get('orderId'))
    loggedIn, fName, itemsNo, userId, isAdmin = getLoginDetails()
    with sqlite3.connect('database.db') as cnn:
        crs = cnn.cursor()
        crs.execute("SELECT orderId, userId, dateTime, totalPrice FROM orders WHERE orderId = ?", (orderId, ))
        order = crs.fetchone()
        if (userId != order[1]) and (not isAdmin):
              return render_template("errorMessage.html", title="Not allowed", message="You don't have the right to view this order!",  loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)
        crs.execute(''' SELECT
                        prods.prodId,
                        prods.name,
                        prods.img,
                        order_prods.qty,
                        order_prods.price,
                        size_values.name as size
                    FROM order_prods
                    LEFT JOIN prods ON
                        order_prods.prodId = prods.prodId
                    LEFT JOIN size_values ON
                        order_prods.sizeId = size_values.idValue
                    WHERE
                        order_prods.orderId = ?
                ''', (orderId,))
        products = crs.fetchall()
        return render_template("orderDetails.html", order=order, products=products, loggedIn=loggedIn, fName=fName, itemsNo=itemsNo, isAdmin=isAdmin)
        
        
                
def allowed_file(filename):
    return '.' in filename and \
            filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


if __name__ == '__main__':
    app.run( port=5000, debug=True)
