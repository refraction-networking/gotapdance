// +build darwin linux windows

package main

import (
	_ "image/png"

	"golang.org/x/mobile/exp/f32"
	"golang.org/x/mobile/exp/sprite"
	"golang.org/x/mobile/exp/sprite/clock"

	"github.com/sergeyfrolov/gotapdance/tdproxy"
)

const (
	desiredScreenWidth = 1080
	mainButtonWidth    = 512
	mainButtonHeight   = 512
	iconWidth          = 192
	iconHeight         = 192
	loremWidth         = 1090
	loremHeight        = 1541
)

const (
	SCENE_NONE = iota
	SCENE_MAIN
	SCENE_HELP
	SCENE_INFO
)

type Scene interface {
	OnTouch(event_x float32, event_y float32)
	Type() int
	GetBackgroundColor() (float32, float32, float32)
	Node() *sprite.Node
}

/*
MAIN_SCENE
*/

type MainScene struct {
	node *sprite.Node

	mainButtonX     float32
	mainButtonY     float32
	infoButtonX     float32
	infoButtonY     float32
	questionButtonX float32
	questionButtonY float32
}

func (s *MainScene) Type() int {
	return SCENE_MAIN
}

func (s *MainScene) Node() *sprite.Node {
	return s.node
}

func (s *MainScene) GetBackgroundColor() (float32, float32, float32) {
	return 0.695, 0.8715, 0.8555
}

func NewMainScene() *MainScene {
	s := new(MainScene)
	s.node = &sprite.Node{}
	spriteEngine.Register(s.node)
	mainSpriteAffine := f32.Affine{
		{1, 0, 0},
		{0, 1, 0},
	}
	mainSpriteAffine.Scale(&mainSpriteAffine, scaleDraw, scaleDraw)
	spriteEngine.SetTransform(s.node, mainSpriteAffine)
	s.mainButtonX = (float32(sizeEvent.WidthPt)/scaleDraw - float32(mainButtonWidth)) / 2
	s.mainButtonY = float32(sizeEvent.HeightPt)/scaleDraw - float32(mainButtonHeight)
	s.infoButtonX = (float32(sizeEvent.WidthPt)/scaleDraw - float32(iconWidth))
	s.infoButtonY = float32(iconHeight) / 3
	s.questionButtonX = (float32(sizeEvent.WidthPt)/scaleDraw - 2*float32(iconWidth))
	s.questionButtonY = float32(iconHeight) / 3

	newSpriteNode(s.node, func(eng sprite.Engine, current_button *sprite.Node, t clock.Time) {
		if proxyLaunched {
			spriteEngine.SetSubTex(current_button, buttonTexStop)
		} else {
			spriteEngine.SetSubTex(current_button, buttonTexLaunch)
		}
		spriteEngine.SetTransform(current_button, f32.Affine{
			{float32(mainButtonWidth), 0, s.mainButtonX},
			{0, float32(mainButtonHeight), s.mainButtonY},
		})
	})
	newSpriteNode(s.node, func(eng sprite.Engine, button *sprite.Node, t clock.Time) {
		spriteEngine.SetSubTex(button, buttonTexQuestion)

		spriteEngine.SetTransform(button, f32.Affine{
			{float32(iconWidth), 0, s.questionButtonX},
			{0, float32(iconHeight), s.questionButtonY},
		})
	})
	newSpriteNode(s.node, func(eng sprite.Engine, button *sprite.Node, t clock.Time) {
		spriteEngine.SetSubTex(button, buttonTexInfo)

		spriteEngine.SetTransform(button, f32.Affine{
			{float32(iconWidth), 0, s.infoButtonX},
			{0, float32(iconHeight), s.infoButtonY},
		})
	})
	return s
}

func (s *MainScene) OnTouch(event_x float32, event_y float32) {
	if event_x > s.mainButtonX && event_x < s.mainButtonX+mainButtonWidth &&
		event_y > s.mainButtonY && event_y < s.mainButtonY+mainButtonHeight {
		if proxyLaunched {
			proxyLaunched = false
			tapdanceProxy.Stop()
			tapdanceProxy = nil
		} else {
			proxyLaunched = true
			tapdanceProxy = tdproxy.NewTapDanceProxy(10500)
			go tapdanceProxy.ListenAndServe()
		}
	} else if event_x > s.infoButtonX && event_x < s.infoButtonX+iconWidth &&
		event_y > s.infoButtonY && event_y < s.infoButtonY+iconHeight {
		setScene(SCENE_INFO)

	} else if event_x > s.questionButtonX && event_x < s.questionButtonX+iconWidth &&
		event_y > s.questionButtonY && event_y < s.questionButtonY+iconHeight {
		setScene(SCENE_HELP)
	}
}

/*
HELP_SCENE
*/

type HelpScene struct {
	node        *sprite.Node
	backButtonX float32
	backButtonY float32
}

func (s *HelpScene) Type() int {
	return SCENE_HELP
}

func (s *HelpScene) Node() *sprite.Node {
	return s.node
}

func (s *HelpScene) GetBackgroundColor() (float32, float32, float32) {
	return 0.0, 0.3, 0.25
}

func NewHelpScene() *HelpScene {
	s := new(HelpScene)
	s.node = &sprite.Node{}
	spriteEngine.Register(s.node)
	mainSpriteAffine := f32.Affine{
		{1, 0, 0},
		{0, 1, 0},
	}
	mainSpriteAffine.Scale(&mainSpriteAffine, scaleDraw, scaleDraw)
	spriteEngine.SetTransform(s.node, mainSpriteAffine)
	s.backButtonX = 0
	s.backButtonY = float32(sizeEvent.HeightPt)/scaleDraw - float32(iconHeight)
	newSpriteNode(s.node, func(eng sprite.Engine, button *sprite.Node, t clock.Time) {
		spriteEngine.SetSubTex(button, buttonTexBack)

		spriteEngine.SetTransform(button, f32.Affine{
			{float32(iconWidth), 0, s.backButtonX},
			{0, float32(iconHeight), s.backButtonY},
		})
	})
	return s
}

func (s *HelpScene) OnTouch(event_x float32, event_y float32) {
	if event_x > s.backButtonX && event_x < s.backButtonX+iconWidth &&
		event_y > s.backButtonY && event_y < s.backButtonY+iconHeight {
		setScene(SCENE_MAIN)
	}
}

/*
INFO_SCENE
*/

type InfoScene struct {
	node        *sprite.Node
	backButtonX float32
	backButtonY float32
}

func (s *InfoScene) Type() int {
	return SCENE_INFO
}

func (s *InfoScene) Node() *sprite.Node {
	return s.node
}

func (s *InfoScene) GetBackgroundColor() (float32, float32, float32) {
	return 0.0, 0.3, 0.25
}

func NewInfoScene() *InfoScene {
	s := new(InfoScene)
	s.node = &sprite.Node{}
	spriteEngine.Register(s.node)
	mainSpriteAffine := f32.Affine{
		{1, 0, 0},
		{0, 1, 0},
	}
	mainSpriteAffine.Scale(&mainSpriteAffine, scaleDraw, scaleDraw)
	spriteEngine.SetTransform(s.node, mainSpriteAffine)
	s.backButtonX = 0
	s.backButtonY = float32(sizeEvent.HeightPt)/scaleDraw - float32(iconHeight)
	newSpriteNode(s.node, func(eng sprite.Engine, button *sprite.Node, t clock.Time) {
		spriteEngine.SetSubTex(button, buttonTexBack)

		spriteEngine.SetTransform(button, f32.Affine{
			{float32(iconWidth), 0, s.backButtonX},
			{0, float32(iconHeight), s.backButtonY},
		})
	})
	newSpriteNode(s.node, func(eng sprite.Engine, button *sprite.Node, t clock.Time) {
		spriteEngine.SetSubTex(button, textLoremTex)

		spriteEngine.SetTransform(button, f32.Affine{
			{float32(loremWidth), 0, 0},
			{0, float32(loremHeight), iconHeight / 3},
		})
	})
	return s
}

func (s *InfoScene) OnTouch(event_x float32, event_y float32) {
	if event_x > s.backButtonX && event_x < s.backButtonX+iconWidth &&
		event_y > s.backButtonY && event_y < s.backButtonY+iconHeight {
		setScene(SCENE_MAIN)
	}
}
