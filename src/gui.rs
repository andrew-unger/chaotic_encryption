use iced::{Application, Command, Element, Settings, Theme};
use iced::widget::{Button, Column, Container, ProgressBar, Radio, Row, Text, TextInput};
use iced::futures::channel::mpsc;
use iced::Length;
use std::path::{Path, PathBuf};
use std::fs;

// Import from the library via external path
extern crate au79_crypto;
use au79_crypto::crypto::{encrypt, decrypt};
use au79_crypto::error::CryptoError;

// Flag enum for application mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Encrypt,
    Decrypt,
    Info,
}

// Message enum for GUI events
#[derive(Debug, Clone)]
pub enum Message {
    ModeSelected(Mode),
    InputPathChanged(String),
    OutputPathChanged(String),
    PasswordChanged(String),
    ConfirmPasswordChanged(String),
    BrowseInputClicked,
    BrowseOutputClicked,
    TogglePasswordVisibility,
    ProcessFile,
    OperationComplete(Result<String, String>),
    FileInfoReceived(String),
}

// Main GUI application state
pub struct Au79Gui {
    mode: Mode,
    input_path: String,
    output_path: String,
    password: String,
    confirm_password: String,
    show_password: bool,
    status: String,
    progress: f32,
    file_info: String,
    processing: bool,
    sender: Option<mpsc::Sender<Message>>,
}

impl Application for Au79Gui {
    type Message = Message;
    type Theme = Theme;
    type Executor = iced::executor::Default;
    type Flags = ();

    fn new(_flags: ()) -> (Self, Command<Message>) {
        (
            Self {
                mode: Mode::Encrypt,
                input_path: String::new(),
                output_path: String::new(),
                password: String::new(),
                confirm_password: String::new(),
                show_password: false,
                status: "Ready.".into(),
                progress: 0.0,
                file_info: String::new(),
                processing: false,
                sender: None,
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("AU79 Cryptography")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::ModeSelected(mode) => {
                self.mode = mode;
                self.status = "Ready.".into();
                self.progress = 0.0;
                self.file_info = String::new();

                // Automatically update output path based on input path
                if !self.input_path.is_empty() {
                    let input_path = PathBuf::from(&self.input_path);
                    
                    match mode {
                        Mode::Encrypt => {
                            let mut output_path = input_path.clone();
                            output_path.set_extension("au79");
                            self.output_path = output_path.to_string_lossy().to_string();
                        },
                        Mode::Decrypt => {
                            let mut output_path = input_path.clone();
                            output_path.set_extension("");
                            self.output_path = output_path.to_string_lossy().to_string();
                        },
                        _ => {}
                    }
                }
            },
            Message::InputPathChanged(path) => {
                self.input_path = path;
                
                // Automatically update output path based on input path
                if !self.input_path.is_empty() {
                    let input_path = PathBuf::from(&self.input_path);
                    
                    match self.mode {
                        Mode::Encrypt => {
                            let mut output_path = input_path.clone();
                            output_path.set_extension("au79");
                            self.output_path = output_path.to_string_lossy().to_string();
                        },
                        Mode::Decrypt => {
                            let mut output_path = input_path.clone();
                            output_path.set_extension("");
                            self.output_path = output_path.to_string_lossy().to_string();
                        },
                        _ => {}
                    }
                }
            },
            Message::OutputPathChanged(path) => {
                self.output_path = path;
            },
            Message::PasswordChanged(password) => {
                self.password = password;
            },
            Message::ConfirmPasswordChanged(password) => {
                self.confirm_password = password;
            },
            Message::BrowseInputClicked => {
                let task = iced::Command::perform(
                    browse_file("Select Input File", false),
                    |result| {
                        match result {
                            Some(path) => Message::InputPathChanged(path),
                            None => Message::InputPathChanged(String::new()),
                        }
                    },
                );
                return task;
            },
            Message::BrowseOutputClicked => {
                let task = iced::Command::perform(
                    browse_file("Select Output File", true),
                    |result| {
                        match result {
                            Some(path) => Message::OutputPathChanged(path),
                            None => Message::OutputPathChanged(String::new()),
                        }
                    },
                );
                return task;
            },
            Message::TogglePasswordVisibility => {
                self.show_password = !self.show_password;
            },
            Message::ProcessFile => {
                if !self.can_process() {
                    return Command::none();
                }
                
                self.processing = true;
                self.progress = 0.1;
                self.status = "Working...".into();
                self.file_info = String::new();
                
                let mode = self.mode;
                let input_path = self.input_path.clone();
                let output_path = self.output_path.clone();
                let password = self.password.clone();
                
                let (sender, _receiver) = mpsc::channel(100);
                self.sender = Some(sender);
                
                return Command::perform(
                    async move {
                        match mode {
                            Mode::Encrypt => {
                                let input = PathBuf::from(input_path);
                                let output = PathBuf::from(output_path);
                                match encrypt_file(&input, &output, &password) {
                                    Ok(msg) => Message::OperationComplete(Ok(msg)),
                                    Err(e) => Message::OperationComplete(Err(e)),
                                }
                            },
                            Mode::Decrypt => {
                                let input = PathBuf::from(input_path);
                                let output = PathBuf::from(output_path);
                                match decrypt_file(&input, &output, &password) {
                                    Ok(msg) => Message::OperationComplete(Ok(msg)),
                                    Err(e) => Message::OperationComplete(Err(e)),
                                }
                            },
                            Mode::Info => {
                                let input = PathBuf::from(input_path);
                                match show_file_info(&input) {
                                    Ok(info) => Message::FileInfoReceived(info),
                                    Err(e) => Message::OperationComplete(Err(e)),
                                }
                            },
                        }
                    },
                    |message| message,
                );
            },
            Message::OperationComplete(result) => {
                self.processing = false;
                match result {
                    Ok(message) => {
                        self.status = message;
                        self.progress = 1.0;
                    },
                    Err(error) => {
                        self.status = format!("Error: {}", error);
                        self.progress = 0.0;
                    },
                }
            },
            Message::FileInfoReceived(info) => {
                self.processing = false;
                self.status = "File information retrieved successfully.".into();
                self.progress = 1.0;
                self.file_info = info;
            },
        }
        
        Command::none()
    }

    fn view(&self) -> Element<Message> {
        // Mode selection row
        let mode_row = Row::new()
            .spacing(20)
            .push(Text::new("Mode:").size(16))
            .push(Radio::new(
                "Encrypt",
                Mode::Encrypt,
                Some(self.mode),
                Message::ModeSelected,
            ))
            .push(Radio::new(
                "Decrypt",
                Mode::Decrypt,
                Some(self.mode),
                Message::ModeSelected,
            ))
            .push(Radio::new(
                "File Info",
                Mode::Info,
                Some(self.mode),
                Message::ModeSelected,
            ));
            
        // Input file row
        let input_row = Row::new()
            .spacing(10)
            .push(Text::new("Input File:").width(Length::Fixed(100.0)))
            .push(
                TextInput::new("Select input file...", &self.input_path)
                    .on_input(Message::InputPathChanged)
                    .padding(5)
                    .width(Length::Fill)
            )
            .push(Button::new(Text::new("Browse")).on_press(Message::BrowseInputClicked));
            
        // Output file row (only for encrypt/decrypt)
        let output_row = if self.mode != Mode::Info {
            Row::new()
                .spacing(10)
                .push(Text::new("Output File:").width(Length::Fixed(100.0)))
                .push(
                    TextInput::new("Select output file...", &self.output_path)
                        .on_input(Message::OutputPathChanged)
                        .padding(5)
                        .width(Length::Fill)
                )
                .push(Button::new(Text::new("Browse")).on_press(Message::BrowseOutputClicked))
        } else {
            Row::new()
        };
        
        // Password row (only for encrypt/decrypt)
        let password_row = if self.mode != Mode::Info {
            let password_input = if self.show_password {
                TextInput::new("Enter password...", &self.password)
                    .on_input(Message::PasswordChanged)
            } else {
                TextInput::new("Enter password...", &self.password)
                    .on_input(Message::PasswordChanged)
                    .password()
            };
            
            Row::new()
                .spacing(10)
                .push(Text::new("Password:").width(Length::Fixed(100.0)))
                .push(password_input.padding(5).width(Length::Fill))
                .push(Button::new(
                    Text::new(if self.show_password { "Hide" } else { "Show" })
                ).on_press(Message::TogglePasswordVisibility))
        } else {
            Row::new()
        };
        
        // Confirm password row (only for encrypt)
        let confirm_row = if self.mode == Mode::Encrypt {
            let confirm_input = if self.show_password {
                TextInput::new("Confirm password...", &self.confirm_password)
                    .on_input(Message::ConfirmPasswordChanged)
            } else {
                TextInput::new("Confirm password...", &self.confirm_password)
                    .on_input(Message::ConfirmPasswordChanged)
                    .password()
            };
            
            Row::new()
                .spacing(10)
                .push(Text::new("Confirm:").width(Length::Fixed(100.0)))
                .push(confirm_input.padding(5).width(Length::Fill))
        } else {
            Row::new()
        };
        
        // Action button
        let button_text = match self.mode {
            Mode::Encrypt => "Encrypt File",
            Mode::Decrypt => "Decrypt File",
            Mode::Info => "Show File Info",
        };
        
        let action_button = Button::new(Text::new(button_text))
            .width(Length::Fixed(150.0))
            .style(iced::theme::Button::Primary);
            
        let action_button = if self.can_process() && !self.processing {
            action_button.on_press(Message::ProcessFile)
        } else {
            action_button
        };
        
        // Status row
        let status_row = Row::new()
            .spacing(10)
            .push(Text::new("Status:").width(Length::Fixed(60.0)))
            .push(Text::new(&self.status).width(Length::Fill));
            
        // Progress bar
        let progress_bar = ProgressBar::new(0.0..=1.0, self.progress)
            .width(Length::Fill);
            
        // File info (only shown when available)
        let file_info = if !self.file_info.is_empty() {
            Column::new()
                .spacing(10)
                .push(Text::new("File Information").size(18))
                .push(Text::new(&self.file_info))
        } else {
            Column::new()
        };
        
        // Main layout
        let content = Column::new()
            .spacing(20)
            .padding(20)
            .push(mode_row)
            .push(input_row)
            .push(output_row)
            .push(password_row)
            .push(confirm_row)
            .push(action_button)
            .push(status_row)
            .push(progress_bar)
            .push(file_info);
            
        Container::new(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .center_y()
            .into()
    }
}

impl Au79Gui {
    fn can_process(&self) -> bool {
        if self.input_path.is_empty() {
            return false;
        }
        
        match self.mode {
            Mode::Encrypt => {
                !self.output_path.is_empty() &&
                !self.password.is_empty() &&
                self.password == self.confirm_password
            },
            Mode::Decrypt => {
                !self.output_path.is_empty() &&
                !self.password.is_empty()
            },
            Mode::Info => {
                true
            },
        }
    }
}

async fn browse_file(title: &str, save: bool) -> Option<String> {
    let dialog = if save {
        rfd::AsyncFileDialog::new().set_title(title).save_file().await
    } else {
        rfd::AsyncFileDialog::new().set_title(title).pick_file().await
    };
    
    dialog.map(|handle| handle.path().to_string_lossy().to_string())
}

fn encrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input file: {}", e))?;
    
    let result = encrypt(&data, password, &input_path.to_string_lossy())
        .map_err(|e| format!("Encryption failed: {}", e))?;
        
    fs::write(output_path, result).map_err(|e| format!("Failed to write output file: {}", e))?;
    
    Ok(format!("File encrypted successfully: {}", output_path.to_string_lossy()))
}

fn decrypt_file(input_path: &Path, output_path: &Path, password: &str) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read input file: {}", e))?;
    
    let (result, extension) = decrypt(&data, password)
        .map_err(|e| match e {
            CryptoError::IntegrityCheckFailed => "Wrong password or file is corrupted.".to_string(),
            _ => format!("Decryption failed: {}", e),
        })?;
        
    let mut final_output = output_path.to_path_buf();
    if !extension.is_empty() {
        final_output.set_extension(&extension);
    }
        
    fs::write(&final_output, result).map_err(|e| format!("Failed to write output file: {}", e))?;
    
    Ok(format!("File decrypted successfully: {}", final_output.to_string_lossy()))
}

fn show_file_info(input_path: &Path) -> Result<String, String> {
    let data = fs::read(input_path).map_err(|e| format!("Failed to read file: {}", e))?;
    
    // First check if this is actually an AU79 file
    if data.len() < 4 || &data[0..4] != b"AU79" {
        return Err("This is not a valid AU79 encrypted file.".to_string());
    }
    
    // Capture the output of display_file_info in a string
    let mut buffer = Vec::new();
    
    buffer.extend_from_slice(b"----- File Info -----\n");
    buffer.extend_from_slice(b"Magic: AU79\n");
    buffer.extend_from_slice(format!("Version: {}\n", data[4]).as_bytes());
    buffer.extend_from_slice(format!("Flags: {}\n", data[5]).as_bytes());
    
    let timestamp_start = 6 + 16; // SALT_LEN = 16
    let timestamp = u64::from_le_bytes(data[timestamp_start..timestamp_start+8].try_into().unwrap());
    buffer.extend_from_slice(format!("Timestamp (Unix Epoch): {}\n", timestamp).as_bytes());
    
    let tent_seed = f64::from_le_bytes(data[timestamp_start+8+12..timestamp_start+8+12+8].try_into().unwrap());
    buffer.extend_from_slice(format!("Tent Map Seed: {:.6}\n", tent_seed).as_bytes());
    
    let ext_len = data[timestamp_start+8+12+8];
    let ext_start = timestamp_start+8+12+8+1;
    let extension = String::from_utf8_lossy(&data[ext_start..ext_start+(ext_len as usize)]);
    buffer.extend_from_slice(format!("Original Extension: .{}\n", extension).as_bytes());
    buffer.extend_from_slice(b"----------------------\n");
    
    Ok(String::from_utf8_lossy(&buffer).to_string())
}

pub fn run_gui() -> Result<(), String> {
    let settings = Settings {
        window: iced::window::Settings {
            size: (600, 500),
            ..Default::default()
        },
        ..Default::default()
    };
    
    Au79Gui::run(settings).map_err(|e| format!("Error running GUI: {}", e))
}