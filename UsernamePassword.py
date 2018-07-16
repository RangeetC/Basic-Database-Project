import pandas as pd
import bcrypt

# Storing the path of Database.csv in a variable.

filepath_const = r"D:\BasicDatabaseProject\Database.csv"


# Storing the database file in a pandas dataframe df.

df = pd.read_csv(filepath_const)

# We will need a list of all the usernames.
username_list = df["Username"].tolist()



# A function to validate the username: to check length, whether it contains
# alphanumeric characters only, and to make sure it doesn't already exist.
# Error messages are appended to a list to be printed later.



def validate_username(usern):
    username_error_list = []          
                     
    if( len(usern) < 4 or len(usern) > 20 ):
        username_error_list.append("Length of username must be between 4 and 20.")
                     
    if( not usern.isalnum() ):
        username_error_list.append("Username cannot contain non-alphanumeric characters.")
        
    if( usern in list(username_list) ):
        username_error_list.append("Username already exists!")

    return username_error_list

# A function to validate the password: to check length, whether it contains
# the username. TODO: Learn regex to check for at least one of
# uppercase, lowercase, and special characters.
# Error messages are appended to a list to be printed later.

def validate_password(usern,passw) :
    password_error_list = []

    if( len(passw) < 8 or len(passw) > 50 ):
        password_error_list.append("Length of password must be between 8 and 50.")

    if( usern in passw ):
        password_error_list.append("Password should not contain username.")

    return password_error_list

# This function is used to add an entry to the database.
# It asks for the username and password, runs the validation
# functions, and adds the entry if valid.
# If username and/or password is invalid, we print the list of errors.

def add_entry():
    global df
    global username_list
    username = input("Enter the username : \n")
    password = input("Enter the password : \n")
    temp_user_error_list = validate_username(username)
    temp_pass_error_list = validate_password(username,password)
    if( (not temp_user_error_list) and (not temp_pass_error_list)):
        
        # bcrypt accepts input only in utf-8, so we encode the string to utf-8 before hashing
        # When adding it back to the database, I ran into trouble unless I decoded it
        # And then encoded it again while checking.
        pass_as_bytes = password.encode('utf-8')
        tempdict = {"Username": username, "Password": bcrypt.hashpw(pass_as_bytes,bcrypt.gensalt()).decode()}
        df = df.append(tempdict, ignore_index=True)
        print("Successfully updated database.")
        # Re-update the username list
        username_list = df["Username"].tolist()
        # Update the database file   
        df.to_csv(filepath_const, mode='w', index=False)
    else: 
        for error in temp_user_error_list:
            print(error)
        for error in temp_pass_error_list:
            print(error)
            


# This function is used to change your password once you've logged in already.
# It takes the index of the username/password row as an input.
# It asks for the new password and updates.

def update_password(login_user,update_index):
    
    confirm_update = input("Are you sure you want to update? Type n to go back, any other key to continue. \n")
    if(confirm_update == 'n' or confirm_update == 'N'):
        return
    successful_update = False
    while(successful_update == False):
        new_password = input("Please enter your new password. \n")
        temp_pass_error_list = validate_password(login_user,new_password)
        if(temp_pass_error_list):
            for error in temp_pass_error_list:
                print(error)
        else:
            new_pass_as_bytes = new_password.encode('utf-8')
            df.at[update_index, "Password"] = bcrypt.hashpw(new_pass_as_bytes,bcrypt.gensalt()).decode()
            print("Successfully updated password.")
            df.to_csv(filepath_const, mode='w', index=False)
            successful_update = True
                               
      
    

# This function is used to log in.
# It asks for a username to check, sees if it exists,
# Then asks for the corresponding password if it does exist.

def log_in():
    global df
    flag = False
    while( flag == False):
        login_user = input("Enter the username to log in: \n")
        user_index = df[df.Username == login_user].index
        # Check for empty df, i.e username doesn't exist
        if( len(user_index) == 0):
            print("Error: Your username does not exist.")
        # Check for duplicates...which should never, ever, ever happen
        elif ( len(user_index) > 1):
            print("There are duplicate usernames, which should never happen. Uh oh.")
            flag = False
        else:
            login_pass = input("Enter the password to log in: \n").encode('utf-8')
            test_pass = df.at[user_index[0], "Password"].encode('utf-8')
            if( bcrypt.checkpw(login_pass, test_pass)):
                print("Successfully logged in!")
                flag = True
            else:
                print("Password does not match.")
    change_choice = input("Enter Y if you want to change your password.\n")
    if(change_choice == 'y' or change_choice == 'Y'):
        update_password(login_user,user_index[0])

        

# This is a basic menu driven program where we ask the user
# for their choice.

print("Welcome to my database!")
print("Here is a list of the rules your username and password must follow: ")
print("1) Your username must be between 4 and 20 characters.")
print("2) Your username can only contain alphanumeric characters.")
print("3) Your username must not already exist in the database.")
print("4) Your password must be between 8 and 50 characters.")
print("5) Your password must not contain your username.")
choice = ""
while(choice != 'X'):
    choice = input("Type 1 to add a new entry, 2 to view the database, 3 to log in, and X to exit.\n")
    if( choice == '1'):
        add_entry()
    elif( choice == '2'):
        print(df.to_csv(sep='\t', index=False))
    elif( choice == '3'):
        log_in()

 
