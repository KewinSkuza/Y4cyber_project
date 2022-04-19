import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
import sys
import json
from PIL import ImageTk, Image
import boto3
import AWS
from ntpath import basename
import scripts
from time import sleep

LARGEFONT =("Verdana", 20)
SMALLFONT = ("Verdana", 12)
TITLEFONT = ("Verdana", 17)
chosen_table = ""

sensitive_fields = []
# setup_complete makes sure that the detection is done only once
setup_completed = False

accountId = ""
access_keys = {}

class tkinterApp(tk.Tk):
    # __init__ function for class tkinterApp
    def __init__(self, *args, **kwargs):
        
        # __init__ function for class Tk
        tk.Tk.__init__(self, *args, **kwargs)
        
        # creating a container
        container = tk.Frame(self) 
        container.pack(side = "top", fill = "both", expand = True)
  
        container.grid_rowconfigure(0, weight = 1)
        container.grid_columnconfigure(0, weight = 1)
  
        # initializing frames to an empty array
        self.frames = {} 
  
        # iterating through a tuple consisting
        # of the different page layouts
        for F in (HomePage, How_To_Use, upload_file, tips):
  
            frame = F(container, self)
  
            # initializing frame of that object from
            # HomePage, how_to_use, upload_file, tips respectively with for loop
            self.frames[F] = frame
            
            frame.grid(row = 0, column = 0, sticky ="nsew")
  
        self.show_frame(HomePage)

    # to display the current frame passed as
    # parameter
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()
        frame['bg'] = "#2D354E"

        separator_vertical = tk.ttk.Separator(self, orient='vertical')
        separator_vertical.place(relx=0.18, rely=0, relwidth=0.001, relheight=1)

        side_separator_horizontal = tk.ttk.Separator(self, orient='horizontal')
        side_separator_horizontal.place(relx=0.0, rely=0.1, relwidth=0.18, relheight=0.001)

        top_separator_horizontal = tk.ttk.Separator(self, orient='horizontal')
        top_separator_horizontal.place(relx=0.18, rely=0.05, relwidth=1, relheight=0.001)

# first window frame HomePage
class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

#-----------Page Title Label---------------
        label = ttk.Label(self, text ="Home", font = LARGEFONT, background='#2D354E', foreground="white")
        label.grid(row = 0, column = 4, padx = 350, pady = 0, rowspan = 4)

#-----------Pad Title---------------
        pad_title = ttk.Label(self, text ="", background='#2D354E')
        pad_title.grid(row = 0, column = 1)

#-----------Project Title---------------
        title = ttk.Label(self, text ="Rec-Encrypt.io", font = TITLEFONT, background='#2D354E')
        title.grid(row = 1, column = 1, padx = 10, pady = 0)

#-----------Padding---------------
        pad = ttk.Label(self, text ="", background='#2D354E', foreground="white")
        pad.grid(row = 5, column = 1, padx = 10, pady = 10)

#-----------Home Page Button---------------
        home_button = ttk.Button(self, text ="Home", command = lambda : controller.show_frame(HomePage))
        home_button.grid(row = 6, column = 1, padx = 10, pady = 10)

#-----------How To Use Button---------------
        how_to_use_button = ttk.Button(self, text ="How To Use", command = lambda : controller.show_frame(How_To_Use))
        how_to_use_button.grid(row = 7, column = 1, padx = 10, pady = 10)

#-----------Upload File Button---------------
        upload_file_button = ttk.Button(self, text ="Upload File", command = lambda : controller.show_frame(upload_file))
        upload_file_button.grid(row = 8, column = 1, padx = 10, pady = 10)
  
#-----------Security Tips Button---------------
        tips_button = ttk.Button(self, text ="Security Tips", command = lambda : controller.show_frame(tips))
        tips_button.grid(row = 9, column = 1, padx = 10, pady = 10)

#-----------Home Page Text---------------
        home_text = ttk.Label(self, text ="Welcome to Rec-encrypt.io!!\n\nThe application to recommend best encryption practices based on your database contents.\n\n To get started simply upload a file. \n\nFor more information on how to use this application visit the how to use page. \n\nFor some security tips visit the tips page.", font = SMALLFONT, wraplength=600, justify="center", background='#2D354E', foreground="white")
        home_text.grid(row=5, column = 4, padx = 10, pady = 10, rowspan=5)


class How_To_Use(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)

#-----------Page Title Label---------------
        label = ttk.Label(self, text ="How To Use", font = LARGEFONT, background='#2D354E', foreground="white")
        label.grid(row = 0, column = 4, padx = 290, pady = 0, rowspan = 4)
  
#-----------Pad Title---------------
        pad_title = ttk.Label(self, text ="", background='#2D354E')
        pad_title.grid(row = 0, column = 1)

#-----------Project Title---------------
        title = ttk.Label(self, text ="Rec-Encrypt.io", font = TITLEFONT, background='#2D354E')
        title.grid(row = 1, column = 1, padx = 10, pady = 0)

#-----------Padding---------------
        pad = ttk.Label(self, text ="", background='#2D354E', foreground="white")
        pad.grid(row = 5, column = 1, padx = 10, pady = 10)

#-----------Home Page Button---------------
        home_button = ttk.Button(self, text ="Home", command = lambda : controller.show_frame(HomePage))
        home_button.grid(row = 6, column = 1, padx = 10, pady = 10)

#-----------How To Use Button---------------
        how_to_use_button = ttk.Button(self, text ="How To Use", command = lambda : controller.show_frame(How_To_Use))
        how_to_use_button.grid(row = 7, column = 1, padx = 10, pady = 10)

#-----------Upload File Button---------------
        upload_file_button = ttk.Button(self, text ="Upload File", command = lambda : controller.show_frame(upload_file))
        upload_file_button.grid(row = 8, column = 1, padx = 10, pady = 10)
  
#-----------Security Tips Button---------------
        tips_button = ttk.Button(self, text ="Security Tips", command = lambda : controller.show_frame(tips))
        tips_button.grid(row = 9, column = 1, padx = 10, pady = 10)

        howtouse_text = ttk.Label(self, text ="When you logged in using your AWS credentials a new user was created with minimum privileges to ensure security. There is a prerequisite to using this application. You will require to export your database as a json file. Ask your System Administrator to provide you with this file. \n\n In order to use this application you must visit the \"Upload File\" page. There you will be presented with a single button named \"Browse files\". \n\n This button will present you with a familiar browse files window which you should use to choose the file you wish to check for sensitive information (i.e., The json file you were given). \n\n This will include the file into the application and the processing can begin. \n\n Next you will be shown buttons that are titled the same as your database fields. After pressing one of the buttons, the sensitive information detection process will begin (This might take from upwards of 15 minutes, depending on the size of your database). \n\n When the processing is finished the results will be displayed to screen.\n\n\nResults:\n\n Any column that has green above it means that the application did not detect any sensitive information. \n\nAny column with red above it is a sensitive field and should be encrypted.", font = SMALLFONT, wraplength=600, justify="center", background='#2D354E', foreground="white")
        howtouse_text.grid(row=5, column = 4, padx = 10, pady = 10, rowspan=40)

class upload_file(tk.Frame):
        def __init__(self, parent, controller):
                tk.Frame.__init__(self, parent)

        #-----------Page Title Label---------------
                label = ttk.Label(self, text ="Upload File", font = LARGEFONT, background='#2D354E', foreground="white")
                label.grid(row = 0, column = 3, rowspan = 2, columnspan=5, padx=(300, 0))

        #-----------Pad Title---------------
                pad_title = ttk.Label(self, text ="", background='#2D354E')
                pad_title.grid(row = 0, column = 1)

        #-----------Project Title---------------
                title = ttk.Label(self, text ="Rec-Encrypt.io", font = TITLEFONT, background='#2D354E')
                title.grid(row = 1, column = 1, padx = 10)

        #-----------Padding---------------
                pad = ttk.Label(self, text ="", background='#2D354E', foreground="white")
                pad.grid(row = 5, column = 1, padx = 10, pady = 10)

        #-----------Home Page Button---------------
                home_button = ttk.Button(self, text ="Home", command = lambda : controller.show_frame(HomePage))
                home_button.grid(row = 3, column = 1, padx = 10, pady = 10)

        #-----------How To Use Button---------------
                how_to_use_button = ttk.Button(self, text ="How To Use", command = lambda : controller.show_frame(How_To_Use))
                how_to_use_button.grid(row = 4, column = 1, padx = 10, pady = 10)

        #-----------Upload File Button---------------
                upload_file_button = ttk.Button(self, text ="Upload File", command = lambda : controller.show_frame(upload_file))
                upload_file_button.grid(row = 5, column = 1, padx = 10, pady = 10)
  
        #-----------Security Tips Button---------------
                tips_button = ttk.Button(self, text ="Security Tips", command = lambda : controller.show_frame(tips))
                tips_button.grid(row = 6, column = 1, padx = 10, pady = 10)

        #-----------Pad Table---------------
                pad_table1 = ttk.Label(self, text ="", background='#2D354E')
                pad_table1.grid(row = 7, column = 1, padx = 10, pady = 10)

        #-----------Pad Table---------------
                pad_table2 = ttk.Label(self, text ="", background='#2D354E')
                pad_table2.grid(row = 8, column = 1, padx = 10, pady = 10)

        #-----------Pad Table---------------
                pad_table3 = ttk.Label(self, text ="", background='#2D354E')
                pad_table3.grid(row = 9, column = 1, padx = 10, pady = 10)
        
        #-----------Pad Browse Files Button---------------
                pad_bw = ttk.Label(self, text="", background='#2D354E')
                pad_bw.grid(row = 2, column = 3, padx = 10, pady = 10)

                filepath = ""
                def browseFiles():
                        # Browse files (only displays json files and folders)
                        global filepath 
                        filepath = filedialog.askopenfilename(initialdir = "/", title = "Select a File", filetypes = (("Json Files", "*.json*"),))
                        if filepath == "":
                                # Empty field
                                wrong_format.configure(text="Please choose a file")
                        elif not ".json" in filepath:
                                # Not a JSON file
                                wrong_format.configure(text="Incorrect file format, make sure to upload JSON files")
                        elif scripts.check_file(filepath):
                                # Make sure it is exported from PhpMyAdmin
                                show_table(filepath)
                        else:
                                # Catch all
                                wrong_format.configure(text="File is not supported by this application (Remember that JSON PHPMyAdmin exports are only supported at this moment)")

                wrong_format = ttk.Label(self, text = "", font = SMALLFONT, wraplength=600, justify="center", background='#2D354E', foreground="red")
                wrong_format.grid(row = 5, column = 3, columnspan=20, padx=(120, 0))

                info_label = ttk.Label(self, text = "Remember to upload a json file. This should be provided by your system administrator.", font = SMALLFONT, wraplength=600, justify="center", background='#2D354E', foreground="white")
                info_label.grid(row = 3, column = 3, columnspan=20, padx=(120, 0))

                # Place the browse files button
                explore_button = ttk.Button(self, text = "Browse Files", command = browseFiles)
                explore_button.grid(row = 4, column = 3, pady = 10, padx=(320, 0))

                def show_table(filepath):
                        # hide browse files button and labels
                        explore_button.grid_forget()
                        info_label.grid_forget()
                        wrong_format.grid_forget()

                        # Get tablenames
                        def get_tablenames(file_name):
                                file = open(file_name)
                                data = json.load(file)
                                tables = []

                                for index in range(0, len(data)):
                                        if 'type' in data[index]:
                                                if data[index]['type'] == 'table':
                                                        tables.append(data[index]['name'])
                                return tables
                        table_names = get_tablenames(filepath)
                        
                        # Choose table to display
                        def choose_table(table_name):
                                global chosen_table 
                                chosen_table = table_name

                        # Legend for safe fields
                        results_legend_green = ttk.Label(self, text ="Green: ", font = SMALLFONT, background='#2D354E', foreground='green')
                        results_legend_green.grid(row = 3, column = 4)

                        results_legend_green_explanation = ttk.Label(self, text ="Not Sensitive fields (No need for encryption)", font = SMALLFONT, background='#2D354E', foreground='white')
                        results_legend_green_explanation.grid(row = 3, column = 5, columnspan=20)

                        # Legend for sensitive fields
                        results_legend_red = ttk.Label(self, text ="Red: ", font = SMALLFONT, background='#2D354E', foreground='red')
                        results_legend_red.grid(row = 4, column = 4)

                        results_legend_red_explanation = ttk.Label(self, text ="Data is sensitive (Must be encrypted)", font = SMALLFONT, background='#2D354E', foreground='white')
                        results_legend_red_explanation.grid(row = 4, column = 5, columnspan=20)

                        # Create the button for every table in file and enter them into an array 
                        table_buttons = []
                        for table in table_names:
                                table_buttons.append(ttk.Button(self, text=table, command=lambda table=table:[choose_table(table), ask_for_table()]))

                        # Place the buttons on screen
                        i_column=4
                        i_row=5
                        for button in table_buttons:
                                # Every 7th button jump down a row to fit it on screen
                                if i_column % 11 == 0:
                                        i_row+=1
                                        i_column=4
                                button.grid(row=i_row, column=i_column, sticky="nw", padx=10, pady=10)
                                i_column+=1

                        # display message saying that the detection might take a while
                        wait = ttk.Label(self, text ="After pressing a button, detection might take from upwards of 15 minutes", font = SMALLFONT, background='#2D354E', foreground='white')
                        wait.grid(row = i_row+1, column = 4, columnspan=20)

                        def ask_for_table():
                                
                                # Get table columns (e.g. username, password, address)
                                def get_table_columns(file_name, tablename):
                                        file = open(file_name)
                                        data = json.load(file)
                                        columns = {}
                                        for index in range(0, len(data)):
                                                if 'data' in data[index]:
                                                        if tablename == data[index]['name']:
                                                                for column in data[index]['data'][0].keys():
                                                                        columns[column] = tablename
                                        return columns
                                
                                # Get the data from each column
                                def get_data(file_name, tablename):
                                        file = open(file_name)
                                        data = json.load(file)
                                        values = []
                                        db_data = []
                                        for index in range(0, len(data)):
                                                if 'data' in data[index]:
                                                        if tablename == data[index]['name']:
                                                                for column in data[index]['data']:
                                                                        for key, value in column.items():
                                                                                values.append(value)
                                                                        val_tuple = tuple(values)
                                                                        db_data.append(val_tuple)
                                                                        values.clear()
                                        return db_data
                                
                                # Headings and data for treeview
                                columns = []
                                column_dict = get_table_columns(filepath, chosen_table)
                                for column, table in column_dict.items():
                                        columns.append(column)
                                db_data = []
                                db_data = get_data(filepath, chosen_table)
                                
                                # Style the treeview
                                style = ttk.Style()
                                style.theme_use("alt")
                                style.configure("Treeview")

                        # SENSITIVITY HEADINGS COLUMN
                                self.heading_tree = ttk.Treeview(self, columns=columns, show='headings', height=1)
                                self.heading_tree.delete(*self.heading_tree.get_children())
                                
                                # define red image
                                red_image = Image.open("red.png")
                                red_image = red_image.resize((400, 10), Image.ANTIALIAS)
                                self.red_image = ImageTk.PhotoImage(red_image)

                                # define green image
                                green_image = Image.open("green.png")
                                green_image = green_image.resize((400, 10), Image.ANTIALIAS)
                                self.green_image = ImageTk.PhotoImage(green_image)

                                def setup_detection(access_keys, filepath, SMALLFONT):
                                        # --- Create bucket if it does not exist ---
                                        # create s3 client with iam credentials
                                        s3_client = boto3.client('s3', aws_access_key_id=access_keys["AccessKeyId"],aws_secret_access_key=access_keys["SecretAccessKey"] )
                                        
                                        # list all buckets to check if the proper bucket exists
                                        bucket_list = s3_client.list_buckets()
                                        bucket_name = 'c00237361projectbucket'

                                        # if bucket does not exist yet, create it and set it to private
                                        if not AWS.bucket_exists(bucket_name, bucket_list):
                                                AWS.create_bucket(bucket_name, s3_client)

                                        # --- Upload file into s3 bucket ---
                                        filename = basename(filepath)
                                        s3_client.upload_file(filepath, bucket_name, filename, ExtraArgs={'ContentType': "application/json"})

                                        # --- Turn on Macie ---
                                        macie_client = boto3.client('macie2', aws_access_key_id=access_keys["AccessKeyId"],aws_secret_access_key=access_keys["SecretAccessKey"], region_name='eu-west-1')
                                        try:
                                                macie_client.enable_macie(
                                                findingPublishingFrequency='FIFTEEN_MINUTES',
                                                status='ENABLED')
                                        except:
                                                # Macie is already enabled
                                                pass

                                        # --- If the email custom identifier is not created yet, create it ---
                                        if not AWS.email_identifier_present(macie_client.list_custom_data_identifiers()):
                                                macie_client.create_custom_data_identifier(
                                                description='Regex expression to identify e-mail addresses',
                                                name='EMAIL_ADDRESS',
                                                regex='[a-zA-Z0-9._-]{3,}@[a-zA-Z0-9.-]{2,}\.[a-zA-Z]{2,4}',)

                                        # Get email identifier id to use in classification job
                                        email_identifer_id = AWS.get_email_identifier_id(macie_client)
                                        custom_identifier_ids = []
                                        custom_identifier_ids.append(email_identifer_id)

                                        # --- Create a classification job for sensitive data detection ---
                                        job_response = macie_client.create_classification_job(
                                                jobType = 'ONE_TIME',
                                                customDataIdentifierIds=custom_identifier_ids,
                                                managedDataIdentifierSelector = 'ALL',
                                                name = 'detect_PII_job',
                                                s3JobDefinition = {
                                                        'bucketDefinitions': [
                                                        {
                                                                'accountId': accountId,
                                                                'buckets': [
                                                                        bucket_name,
                                                                ]
                                                        },
                                                        ],
                                                },
                                                samplingPercentage=100)
                                        
                                        # --- Get job id ---
                                        jobId = job_response['jobId']

                                        # --- Wait for the job to finish ---
                                        AWS.wait_for_job(jobId, macie_client)
                                        
                                        # --- Get and parse findings ---
                                        findings = AWS.get_findings(macie_client)
                                        macie_fields = AWS.parse_results(findings, filepath)

                                        # --- Custom detection (passwords, addresses) ---
                                        password_fields = scripts.check_for_password_field(filepath)

                                        already_sensitive = password_fields + macie_fields
                                        address_fields = scripts.check_for_address_field(filepath, already_sensitive)

                                        # --- Merge detections into a single list ---
                                        global sensitive_fields
                                        sensitive_fields = password_fields + address_fields + macie_fields

                                        # Estimate Encryption Time
                                        approx_file = open(filepath)
                                        approx_data = json.load(approx_file)
                                        approx_encrypt = "If you were to encrypt this data it would take approximately: " + scripts.calculate_encryption_time(approx_data) + " seconds"
                                        results_legend_red_explanation = ttk.Label(self, text = approx_encrypt, font = SMALLFONT, background='#2D354E', foreground='white')
                                        results_legend_red_explanation.grid(row = 2, column = 4, columnspan=20)

                                        # --- Cleanup after processing ---
                                        # make sure detection is done once per app launch
                                        global setup_completed
                                        setup_completed = True

                                        # Delete the file from bucket after processing
                                        AWS.delete_from_bucket(filename, bucket_name, s3_client)

                                        # Disable macie service after use (clears findings in AWS console)
                                        macie_client.disable_macie()

                                global setup_completed
                                # Only run detection once per application launch
                                if setup_completed == False:
                                        setup_detection(access_keys, filepath, SMALLFONT)
                                        # remove the wait message after processing is finished
                                        wait.grid_forget()
                                
                                # Populate headings and assign sensitivity color
                                detected = []
                                for index in range(0, len(sensitive_fields)):
                                        for col in columns:
                                                # if sensitive change to red else to green 
                                                for item in sensitive_fields[index].keys():
                                                        if col == item and sensitive_fields[index][col] == chosen_table:
                                                                detected.append(col)
                                                                self.heading_tree.heading(col, text=col, image=self.red_image)
                                                        elif (col not in detected):
                                                                self.heading_tree.heading(col, text=col, image=self.green_image)

                                self.heading_tree.grid(row=i_row+1, column=4, sticky='nswe', padx=5, pady=25, rowspan=2, columnspan=20)

                        # DATA TREE
                                self.tree = ttk.Treeview(self, columns=columns, show='headings', height=20)
                                self.tree.delete(*self.tree.get_children())
                                
                                # define headings
                                for col in columns:
                                        self.tree.heading(col, text=col)
                                # insert data
                                for contact in db_data:
                                        self.tree.insert('', tk.END, values=contact)
                                
                                for re_col in columns:
                                        self.tree.column(re_col, width=50, minwidth=100)
                                
                                for re_hed_col in columns:
                                        self.heading_tree.column(re_hed_col, width=50, minwidth=100)

                                tree_span = 20
                                self.tree.grid(row=i_row+2, column=4, sticky='nswe', rowspan=tree_span, padx=5, columnspan=20)

                                # add a vertical scrollbar scrollbar
                                ver_scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
                                self.tree.configure(yscrollcommand=ver_scrollbar.set)
                                ver_scrollbar.grid(row=i_row+2, column=23, sticky='nes', rowspan=tree_span, padx=5)

                                # Allows for the headings tree and normal tree to share horizontal scrollbar
                                def multiple_scroll(*args):
                                        self.tree.xview(*args)
                                        self.heading_tree.xview(*args)

                                # Add a horizontal scrollbar
                                hor_scrollbar = ttk.Scrollbar(self, orient=tk.HORIZONTAL)
                                self.tree.configure(xscrollcommand=hor_scrollbar.set)
                                hor_scrollbar.configure(command=multiple_scroll)
                                hor_scrollbar.grid(row=i_row+22, column=4, sticky='swe', columnspan=20, padx=5)

class tips(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
#-----------Page Title Label---------------
        label = ttk.Label(self, text ="Security Tips", font = LARGEFONT, background='#2D354E', foreground="white")
        label.grid(row = 0, column = 4, padx = 300, pady = 0, rowspan = 4)

#-----------Pad Title---------------
        pad_title = ttk.Label(self, text ="", background='#2D354E')
        pad_title.grid(row = 0, column = 1)

#-----------Project Title---------------
        title = ttk.Label(self, text ="Rec-Encrypt.io", font = TITLEFONT, background='#2D354E')
        title.grid(row = 1, column = 1, padx = 10, pady = 0)

#-----------Padding---------------
        pad = ttk.Label(self, text ="", background='#2D354E', foreground="white")
        pad.grid(row = 5, column = 1, padx = 10, pady = 10)

#-----------Home Page Button---------------
        home_button = ttk.Button(self, text ="Home", command = lambda : controller.show_frame(HomePage))
        home_button.grid(row = 6, column = 1, padx = 10, pady = 10)

#-----------How To Use Button---------------
        how_to_use_button = ttk.Button(self, text ="How To Use", command = lambda : controller.show_frame(How_To_Use))
        how_to_use_button.grid(row = 7, column = 1, padx = 10, pady = 10)

#-----------Upload Button Button---------------
        upload_file_button = ttk.Button(self, text ="Upload File", command = lambda : controller.show_frame(upload_file))
        upload_file_button.grid(row = 8, column = 1, padx = 10, pady = 10)
  
#-----------Security Tips Button---------------
        tips_button = ttk.Button(self, text ="Security Tips", command = lambda : controller.show_frame(tips))
        tips_button.grid(row = 9, column = 1, padx = 10, pady = 10)

        tips_text = ttk.Label(self, text ="Just encrypting your data might not be enough to secure it. There are a few important things to consider: \n\n         - Any encryption should be performed using a secure encryption algorithm (An industry standard includes AES) \n\n       - Even though you can use a secure encryption algorithm, it still might be implemented incorrectly. Here are some pointers on how to incorporate secure encryption:\n           - Use a sufficient key size (A small key size might render the encryption unsecure)\n            - Do your research; choosing the right software can make the difference. Getting a security professional to incorporate encryption for you might be a good idea instead of trying to do it yourself\n          - Keep the encryption key secure (It is a bad idea to store it in plaintext), if the attacker acquires your encryption key, your data would be unprotected.\n\n   - It is important to encrypt your data not only when you store it but also in transit.\n\n      - When it comes to password fields, encryption is not the ideal solution. Using salted hashes is much preferred. You must also use a secure hashing algorithm. My recommendation includes SHA-256 which is still considered the industry standard.\n\n        - Data that should be encrypted in a database is anything that can identify a person like name, address, date of birth, etc. Also, any data that might be considered sensitive information like username, password, access keys etc.\n\n      - It is a good idea to double check if everything sensitive is encrypted. Not complying with GDPR can lead to fines.", font = SMALLFONT, wraplength=600, justify="center", background='#2D354E', foreground="white")
        tips_text.grid(row=5, column = 4, padx = 10, pady = 10, rowspan=40)

# Driver Code
app = tkinterApp()
app.geometry("1024x768")
app.resizable(False, False)
app.title("Encryption Recommendation")

top = tk.Toplevel() #Creates the toplevel window
top.geometry("512x700")
top.resizable(False, False)
top.title("Login Page")
top['bg'] = "#2D354E"

aws_account_text = ttk.Label(top, text ="This application checks your database for potentially sensitive information and recommends relevant data for encryption.\n\nNo data encryption is performed.\n\n Only PHPMyAdmin database export is supported at the moment. \n\nYou must have an AWS account to use this application, you can create one at aws.amazon.com\n\nIn order to generate security credentials visit the aws website, log in and press your username at the top right corner of your AWS console choosing \"Security Credentials\". From there you will be able to see \"Access Keys\". In this menu you can generate your keys.\n\n Make sure you do not share these keys with anyone. It is even a better idea to delete them after use.", font = SMALLFONT, wraplength=500, justify="center", background='#2D354E', foreground="white")
aws_account_text.grid(row=0, column = 1, padx = 10, pady = 10, columnspan=20)


separator = ttk.Label(top, text ="=========================================================", background='#2D354E', foreground="white")
separator.grid(row=1, column = 0, columnspan=20)


padding = ttk.Label(top, text ="                             ", background='#2D354E')
padding.grid(row=2, column = 3, padx = 10, pady = 10)

access_key_id_label = ttk.Label(top, text ="Access Key ID", font = SMALLFONT, justify="center", background='#2D354E', foreground="white")
access_key_id_label.grid(row = 2, column = 4, padx = 10, pady = 10)

access_key_id_entry = ttk.Entry(top)
access_key_id_entry.grid(row = 3, column = 4, padx = 10, pady = 10)

secret_access_key_label = ttk.Label(top, text ="Secret Access Key", font = SMALLFONT, justify="center", background='#2D354E', foreground="white")
secret_access_key_label.grid(row = 4, column = 4, padx = 10, pady = 10)

secret_access_key_entry = ttk.Entry(top, show="*")
secret_access_key_entry.grid(row = 5, column = 4, padx = 10, pady = 10)

login_button = ttk.Button(top, text="Login", command=lambda:command1()) #Login button
login_button.grid(row = 8, column = 4, padx = 10, pady = 10)

cancel_button = ttk.Button(top, text="Cancel", command=lambda:command2()) #Cancel button
cancel_button.grid(row = 9, column = 4, padx = 10, pady = 10)
def command1():
        # Login button was pressed (Authenticate the user)
        sts_root = boto3.client('sts', aws_access_key_id=access_key_id_entry.get(), aws_secret_access_key=secret_access_key_entry.get())
        try:
                # On valid credentials prepare the work environment
                sts_root.get_caller_identity()
                # Anything past caller identity is authenticated
        
                # Create IAM client
                iam = boto3.client('iam', aws_access_key_id=access_key_id_entry.get(), aws_secret_access_key=secret_access_key_entry.get())

                if not AWS.user_exists("rec-encrypt_user", iam):
                        # Create user that is going to be used for aws boto3 requests
                        AWS.create_user("rec-encrypt_user", iam)

                if not AWS.policy_exists("rec-encrypt_policy", iam):
                        # Create user policy to restrict access to not needed resources
                        policy_arn = AWS.create_policy("rec-encrypt_policy", iam)
                else:
                        policy_arn = AWS.policy_exists("rec-encrypt_policy", iam)

                # Attach the policy to iam user
                AWS.bind_policy_to_user("rec-encrypt_user", policy_arn, iam)

                # Create temporary access keys for the user (From here on out the access keys used should be the ones of this user of least privilege)
                global access_keys 
                access_keys = AWS.create_access_keys("rec-encrypt_user", iam)
                # Need to wait until access keys are generated on amazon side
                sleep(10)

                global accountId
                sts = boto3.client('sts', aws_access_key_id=access_keys['AccessKeyId'], aws_secret_access_key=access_keys['SecretAccessKey'])
                # get created account id for classification job
                accountId = AWS.get_accountId(sts)

                app.deiconify() #Unhides the app window
                top.destroy() #Removes the toplevel window
        except sts_root.exceptions.ClientError:
                # Invalid Credentials
                inv_cred_label = ttk.Label(top, text="Invalid Credentials, try again", font = SMALLFONT, justify='left', background='#2D354E', foreground="red")
                inv_cred_label.grid(row = 6, column = 3, columnspan=20)

def command2():
        # Cancel button was pressed (Close window)
        top.destroy() #Removes the toplevel window
        app.destroy() #Removes the hidden app window
        sys.exit() #Ends the script

app.withdraw()

def on_closing():
        # On application exit delete access keys
        try:
                iam = boto3.client('iam', aws_access_key_id=access_keys["AccessKeyId"],aws_secret_access_key=access_keys["SecretAccessKey"] )
                AWS.delete_access_keys("rec-encrypt_user", access_keys["AccessKeyId"], iam)
        except:
                pass
        finally:
                top.destroy() #Removes the toplevel window
                app.destroy() #Removes the hidden app window
                sys.exit() #Ends the script

# Perform actions before exit
app.protocol("WM_DELETE_WINDOW", on_closing)

# Lanuch app
app.mainloop()