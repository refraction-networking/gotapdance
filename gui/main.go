// +build darwin linux windows

package main

import (
	"image"
	_ "image/png"
	"time"

	"golang.org/x/mobile/app"
	"golang.org/x/mobile/asset"
	"golang.org/x/mobile/gl"

	"golang.org/x/mobile/event/lifecycle"
	"golang.org/x/mobile/event/paint"
	"golang.org/x/mobile/event/size"
	"golang.org/x/mobile/event/touch"

	"golang.org/x/mobile/exp/gl/glutil"
	"golang.org/x/mobile/exp/sprite"
	"golang.org/x/mobile/exp/sprite/clock"
	"golang.org/x/mobile/exp/sprite/glsprite"

	"github.com/SergeyFrolov/gotapdance/tdproxy"
)

var (
	startTime = time.Now()

	glctx gl.Context

	glutilImages *glutil.Images
	spriteEngine sprite.Engine

	currentScene Scene

	sizeEvent size.Event
	scaleDraw = float32(1)

	buttonTexLaunch   sprite.SubTex
	buttonTexStop     sprite.SubTex
	buttonTexQuestion sprite.SubTex
	buttonTexBack     sprite.SubTex
	buttonTexInfo     sprite.SubTex
	textLoremTex      sprite.SubTex

	proxyLaunched bool
	tapdanceProxy *tdproxy.TapDanceProxy
)

type arrangerFunc func(e sprite.Engine, n *sprite.Node, t clock.Time)

func (a arrangerFunc) Arrange(e sprite.Engine, n *sprite.Node, t clock.Time) {
	a(e, n, t)
}

func main() {
	app.Main(func(app app.App) {
		for event := range app.Events() {
			switch event := app.Filter(event).(type) {
			case lifecycle.Event:
				switch event.Crosses(lifecycle.StageVisible) {
				case lifecycle.CrossOn:
					onStart(event)
					app.Send(paint.Event{})
				case lifecycle.CrossOff:
					onStop()
				}
			case size.Event:
				onSizeEvent(event)
				app.Send(paint.Event{})
			case paint.Event:
				if glctx == nil || event.External {
					continue
				}
				onPaint()
				app.Publish()
				app.Send(paint.Event{}) // keep animating
			case touch.Event:
				//if down := event.Type == touch.TypeBegin; down || event.Type == touch.TypeEnd {
				if event.Type == touch.TypeEnd {
					onTouch(event)
				}
				app.Send(paint.Event{})
			}
		}
	})
}

func onSizeEvent(event size.Event) {
	sizeEvent = event

	scaleDraw = float32(sizeEvent.WidthPt) / desiredScreenWidth
	if currentScene != nil {
		setScene(currentScene.Type())
	}
}

func setScene(sceneType int) {
	if currentScene != nil {
		// sprite_engine.Unregister(current_scene)
		// Unregister() is still not implemented. Let Mr. Garbage Collector take care of it
		currentScene = nil
	}
	switch sceneType {
	case SCENE_MAIN:
		currentScene = NewMainScene()
	case SCENE_HELP:
		currentScene = NewHelpScene()
	case SCENE_INFO:
		currentScene = NewInfoScene()
	case SCENE_NONE:
	}
}

func onStart(event lifecycle.Event) {
	glctx, _ = event.DrawContext.(gl.Context)
	glutilImages = glutil.NewImages(glctx)
	spriteEngine = glsprite.Engine(glutilImages)

	buttonTexLaunch = loadRectSpriteAsset("teal_launch.png", mainButtonWidth, mainButtonHeight)
	buttonTexStop = loadRectSpriteAsset("teal_stop.png", mainButtonWidth, mainButtonHeight)
	buttonTexQuestion = loadRectSpriteAsset("teal_question.png", iconWidth, iconHeight)
	buttonTexInfo = loadRectSpriteAsset("teal_info.png", iconWidth, iconHeight)
	buttonTexBack = loadRectSpriteAsset("teal_back.png", iconWidth, iconHeight)
	textLoremTex = loadRectSpriteAsset("lorem.png", loremWidth, loremHeight)
	setScene(SCENE_MAIN)
}

func onStop() {
	setScene(SCENE_NONE)
	spriteEngine.Release()
	glutilImages.Release()
	glctx = nil
}

func onPaint() {
	if currentScene != nil {
		r, g, b := currentScene.GetBackgroundColor()
		glctx.ClearColor(r, g, b, 1)

		glctx.Clear(gl.COLOR_BUFFER_BIT)
		now := clock.Time(time.Since(startTime) * 60 / time.Second)
		spriteEngine.Render(currentScene.Node(), now, sizeEvent)
	}
}

func onTouch(event touch.Event) {
	actualScreenHeight := float32(sizeEvent.HeightPt) / scaleDraw
	eventX := event.X * actualScreenHeight / float32(sizeEvent.HeightPx)
	eventY := event.Y * desiredScreenWidth / float32(sizeEvent.WidthPx)

	currentScene.OnTouch(eventX, eventY)
}

func loadRectSpriteAsset(spriteFilename string, width int, height int) sprite.SubTex {
	// TODO: handle errors
	imgFile, err := asset.Open(spriteFilename)
	if err != nil {
		panic(err)
	}
	defer imgFile.Close()

	img, _, err := image.Decode(imgFile)
	if err != nil {
		panic(err)
	}
	texture, err := spriteEngine.LoadTexture(img)
	if err != nil {
		panic(err)
	}

	return sprite.SubTex{texture, image.Rect(0, 0, width, height)}
}

func newSpriteNode(n *sprite.Node, fn arrangerFunc) (spriteNode *sprite.Node) {
	spriteNode = &sprite.Node{Arranger: arrangerFunc(fn)}
	spriteEngine.Register(spriteNode)
	n.AppendChild(spriteNode)
	return
}
