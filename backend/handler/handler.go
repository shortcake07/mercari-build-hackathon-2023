package handler

import (
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/labstack/echo/v4"
	"github.com/mizukitayama/mecari-build-hackathon-2023/backend/db"
	"github.com/mizukitayama/mecari-build-hackathon-2023/backend/domain"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

const (
	MAX_FILE_SIZE = 1024 * 300
)

var (
	logFile = getEnv("LOGFILE", "access.log")
)

type JwtCustomClaims struct {
	UserID int64 `json:"user_id"`
	jwt.RegisteredClaims
}

type InitializeResponse struct {
	Message string `json:"message"`
}

type registerRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type registerResponse struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type getUserItemsResponse struct {
	ID           int32             `json:"id"`
	Name         string            `json:"name"`
	Price        int64             `json:"price"`
	CategoryName string            `json:"category_name"`
	Status       domain.ItemStatus `json:"status"`
}

type getOnSaleItemsResponse struct {
	ID           int32             `json:"id"`
	Name         string            `json:"name"`
	Price        int64             `json:"price"`
	CategoryName string            `json:"category_name"`
	Status       domain.ItemStatus `json:"status"`
}

type getItemResponse struct {
	ID           int32             `json:"id"`
	Name         string            `json:"name"`
	CategoryID   int64             `json:"category_id"`
	CategoryName string            `json:"category_name"`
	UserID       int64             `json:"user_id"`
	Price        int64             `json:"price"`
	Description  string            `json:"description"`
	Status       domain.ItemStatus `json:"status"`
}

type getCategoriesResponse struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

type sellRequest struct {
	ItemID int32 `json:"item_id"`
	Price  int64 `form:"price"`
}

type addItemRequest struct {
	Name        string `form:"name"`
	CategoryID  int64  `form:"category_id"`
	Price       int64  `form:"price"`
	Description string `form:"description"`
}

type addItemResponse struct {
	ID    int64 `json:"id"`
	Price int64 `json:"price"`
}

type updateItemRequest struct {
	Name        string `form:"name"`
	CategoryID  int64  `form:"category_id"`
	Price       int64  `form:"price"`
	Description string `form:"description"`
}

type updateItemResponse struct {
	ID int64 `json:"id"`
}

type addBalanceRequest struct {
	Balance int64 `json:"balance"`
}

type getBalanceResponse struct {
	Balance int64 `json:"balance"`
}

type loginRequest struct {
	UserID   int64  `json:"user_id"`
	Password string `json:"password"`
}

type loginResponse struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Token string `json:"token"`
}

type Handler struct {
	DB       *sql.DB
	UserRepo db.UserRepository
	ItemRepo db.ItemRepository
}

func GetSecret() string {
	if secret := os.Getenv("SECRET"); secret != "" {
		return secret
	}
	return "secret-key"
}

func (h *Handler) Initialize(c echo.Context) error {
	err := os.Truncate(logFile, 0)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, errors.Wrap(err, "Failed to truncate access log"))
	}

	err = db.Initialize(c.Request().Context(), h.DB)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, errors.Wrap(err, "Failed to initialize"))
	}

	return c.JSON(http.StatusOK, InitializeResponse{Message: "Success"})
}

func (h *Handler) AccessLog(c echo.Context) error {
	return c.File(logFile)
}

func (h *Handler) Register(c echo.Context) error {
	// TODO: validation
	// http.StatusBadRequest(400)
	req := new(registerRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	userID, err := h.UserRepo.AddUser(c.Request().Context(), domain.User{Name: req.Name, Password: string(hash)})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, registerResponse{ID: userID, Name: req.Name})
}

func (h *Handler) Login(c echo.Context) error {
	ctx := c.Request().Context()
	// TODO: validation
	// http.StatusBadRequest(400)
	req := new(loginRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	user, err := h.UserRepo.GetUser(ctx, req.UserID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return echo.NewHTTPError(http.StatusUnauthorized, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	// Set custom claims
	claims := &JwtCustomClaims{
		req.UserID,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 72)),
		},
	}
	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Generate encoded token and send it as response.
	encodedToken, err := token.SignedString([]byte(GetSecret()))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, loginResponse{
		ID:    user.ID,
		Name:  user.Name,
		Token: encodedToken,
	})
}

func (h *Handler) AddItem(c echo.Context) error {
	// TODO: validation
	// http.StatusBadRequest(400)
	ctx := c.Request().Context()

	req := new(addItemRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	if req.Price <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Price must be greater than 0")
	}

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	file, err := c.FormFile("image")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	src, err := file.Open()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	defer src.Close()

	var dest []byte
	blob := bytes.NewBuffer(dest)
	if _, err := io.Copy(blob, src); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	_, err = h.ItemRepo.GetCategory(ctx, req.CategoryID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid categoryID")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	item, err := h.ItemRepo.AddItem(c.Request().Context(), domain.Item{
		Name:        req.Name,
		CategoryID:  req.CategoryID,
		UserID:      userID,
		Price:       req.Price,
		Description: req.Description,
		Image:       blob.Bytes(),
		Status:      domain.ItemStatusInitial,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, addItemResponse{ID: int64(item.ID), Price: int64(item.Price)})
}

func (h *Handler) Sell(c echo.Context) error {
	ctx := c.Request().Context()
	req := new(sellRequest)

	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}
	if req.Price <= 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "Price must be greater than 0")
	}

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	item, err := h.ItemRepo.GetItem(ctx, req.ItemID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusPreconditionFailed, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	if userID != item.UserID {
		return echo.NewHTTPError(http.StatusPreconditionFailed, err)
	}

	if item.Status != 1 {
		return echo.NewHTTPError(http.StatusPreconditionFailed, err)
	}
	if err := h.ItemRepo.UpdateItemStatus(ctx, item.ID, domain.ItemStatusOnSale); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, "successful")
}

func (h *Handler) UpdateItem(c echo.Context) error {
	ctx := c.Request().Context()

	itemID, err := strconv.Atoi(c.Param("itemID"))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid item ID")
	}

	req := new(updateItemRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}
	if err := c.Request().ParseMultipartForm(10 << 20); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	file, err := c.FormFile("image")
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	src, err := file.Open()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	defer src.Close()

	var dest []byte
	blob := bytes.NewBuffer(dest)
	if _, err := io.Copy(blob, src); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	_, err = h.ItemRepo.GetCategory(ctx, req.CategoryID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid categoryID")
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	item, err := h.ItemRepo.UpdateItem(c.Request().Context(), domain.Item{
		ID:          int32(itemID),
		Name:        req.Name,
		CategoryID:  req.CategoryID,
		UserID:      userID,
		Price:       req.Price,
		Description: req.Description,
		Image:       blob.Bytes(),
		Status:      domain.ItemStatusInitial,
	})
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, updateItemResponse{ID: int64(item.ID)})
}

func (h *Handler) GetOnSaleItems(c echo.Context) error {
	ctx := c.Request().Context()

	items, err := h.ItemRepo.GetOnSaleItems(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	var res []getOnSaleItemsResponse
	for _, item := range items {
		cats, err := h.ItemRepo.GetCategories(ctx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		for _, cat := range cats {
			if cat.ID == item.CategoryID {
				res = append(res, getOnSaleItemsResponse{ID: item.ID, Name: item.Name, Price: item.Price, CategoryName: cat.Name, Status: item.Status})
			}
		}
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) GetItem(c echo.Context) error {
	ctx := c.Request().Context()

	itemID, err := strconv.ParseInt(c.Param("itemID"), 10, 32)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	item, err := h.ItemRepo.GetItem(ctx, int32(itemID))
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	category, err := h.ItemRepo.GetCategory(ctx, item.CategoryID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	return c.JSON(http.StatusOK, getItemResponse{
		ID:           item.ID,
		Name:         item.Name,
		CategoryID:   item.CategoryID,
		CategoryName: category.Name,
		UserID:       item.UserID,
		Price:        item.Price,
		Description:  item.Description,
		Status:       item.Status,
	})
}

func (h *Handler) GetUserItems(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := strconv.ParseInt(c.Param("userID"), 10, 64)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid userID type")
	}

	items, err := h.ItemRepo.GetItemsByUserID(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	var res []getUserItemsResponse
	for _, item := range items {
		cats, err := h.ItemRepo.GetCategories(ctx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, err)
		}
		for _, cat := range cats {
			if cat.ID == item.CategoryID {
				res = append(res, getUserItemsResponse{ID: item.ID, Name: item.Name, Price: item.Price, CategoryName: cat.Name, Status: item.Status})
			}
		}
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) GetCategories(c echo.Context) error {
	ctx := c.Request().Context()

	cats, err := h.ItemRepo.GetCategories(ctx)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusNotFound, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	res := make([]getCategoriesResponse, len(cats))
	for i, cat := range cats {
		res[i] = getCategoriesResponse{ID: cat.ID, Name: cat.Name}
	}

	return c.JSON(http.StatusOK, res)
}

func (h *Handler) GetImage(c echo.Context) error {
	ctx := c.Request().Context()

	itemID, err := strconv.ParseInt(c.Param("itemID"), 10, 32)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "invalid itemID type")
	}

	data, err := h.ItemRepo.GetItemImage(ctx, int32(itemID))
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.Blob(http.StatusOK, "image/jpeg", data)
}

func (h *Handler) AddBalance(c echo.Context) error {
	ctx := c.Request().Context()

	req := new(addBalanceRequest)
	if err := c.Bind(req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err)
	}

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	user, err := h.UserRepo.GetUser(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusPreconditionFailed, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if user.Balance+req.Balance >= 0 {
		if err := h.UserRepo.UpdateBalance(ctx, userID, user.Balance+req.Balance); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}
	} else {
		if err := h.UserRepo.UpdateBalance(ctx, userID, user.Balance); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}
	}

	return c.JSON(http.StatusOK, "successful")
}

func (h *Handler) GetBalance(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	user, err := h.UserRepo.GetUser(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusPreconditionFailed, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, getBalanceResponse{Balance: user.Balance})
}

func (h *Handler) Purchase(c echo.Context) error {
	ctx := c.Request().Context()

	userID, err := getUserID(c)
	if err != nil {
		return echo.NewHTTPError(http.StatusUnauthorized, err)
	}

	itemID, err := strconv.ParseInt(c.Param("itemID"), 10, 32)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	user, err := h.UserRepo.GetUser(ctx, userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusPreconditionFailed, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	item, err := h.ItemRepo.GetItem(ctx, int32(itemID))
	if err != nil {
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusPreconditionFailed, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if user.Balance >= item.Price {
		if item.Status != 2 {
			return echo.NewHTTPError(http.StatusPreconditionFailed, err)
		}
		if err := h.ItemRepo.UpdateItemStatus(ctx, int32(itemID), domain.ItemStatusSoldOut); err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, err)
		}
		if item.UserID == userID {
			h.ItemRepo.UpdateItemStatus(ctx, int32(itemID), domain.ItemStatusOnSale)
			return echo.NewHTTPError(http.StatusPreconditionFailed, "not to buy own item")
		}
	} else {
		return echo.NewHTTPError(http.StatusPaymentRequired, "payment require")
	}

	var sellerID = item.UserID
	seller, err := h.UserRepo.GetUser(ctx, sellerID)
	if err != nil {
		h.ItemRepo.UpdateItemStatus(ctx, int32(itemID), domain.ItemStatusOnSale)
		if err == sql.ErrNoRows {
			return echo.NewHTTPError(http.StatusPreconditionFailed, err)
		}
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	if err := h.UserRepo.UpdateBalance(ctx, userID, user.Balance-item.Price); err != nil {
		h.ItemRepo.UpdateItemStatus(ctx, int32(itemID), domain.ItemStatusOnSale)
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}
	if err := h.UserRepo.UpdateBalance(ctx, sellerID, seller.Balance+item.Price); err != nil {
		h.ItemRepo.UpdateItemStatus(ctx, int32(itemID), domain.ItemStatusOnSale)
		h.UserRepo.UpdateBalance(ctx, userID, user.Balance+item.Price)
		return echo.NewHTTPError(http.StatusInternalServerError, err)
	}

	return c.JSON(http.StatusOK, "successful")
}

func getUserID(c echo.Context) (int64, error) {
	user := c.Get("user").(*jwt.Token)
	if user == nil {
		return -1, fmt.Errorf("invalid token")
	}
	claims := user.Claims.(*JwtCustomClaims)
	if claims == nil {
		return -1, fmt.Errorf("invalid token")
	}

	return claims.UserID, nil
}

func getEnv(key string, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
