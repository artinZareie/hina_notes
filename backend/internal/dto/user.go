package dto

type UpdateProfileRequest struct {
	Name string `json:"name" binding:"required,min=1,max=100"`
}

type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=128"`
}
