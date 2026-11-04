package ffmpeg

import (
	"context"
	"go.uber.org/zap"
	"mime"
	"strings"

	"github.com/go-flac/flacpicture"
	"github.com/go-flac/flacvorbis"
	"github.com/go-flac/go-flac"
	"golang.org/x/exp/slices"
)

func updateMetaFlac(_ context.Context, outPath string, m *UpdateMetadataParams, logger *zap.Logger) error {
	f, err := flac.ParseFile(m.Audio)
	if err != nil {
		return err
	}

	// generate comment block
	comment := flacvorbis.MetaDataBlockVorbisComment{Vendor: "unlock-music.dev"}

	// add metadata
	title := m.Meta.GetTitle()
	if title != "" {
		_ = comment.Add(flacvorbis.FIELD_TITLE, title)
	}

	album := m.Meta.GetAlbum()
	if album != "" {
		_ = comment.Add(flacvorbis.FIELD_ALBUM, album)
	}

	artists := m.Meta.GetArtists()
	for _, artist := range artists {
		_ = comment.Add(flacvorbis.FIELD_ARTIST, artist)
	}

	existCommentIdx := slices.IndexFunc(f.Meta, func(b *flac.MetaDataBlock) bool {
		return b.Type == flac.VorbisComment
	})
	if existCommentIdx >= 0 { // keep existing fields we do not overwrite
		exist, err := flacvorbis.ParseFromMetaDataBlock(*f.Meta[existCommentIdx])
		if err != nil {
			// Never touch exist on error: the parser returns a nil pointer there.
			logger.Warn("failed to parse existing vorbis comment block, tags will be replaced", zap.Error(err))
		} else {
			for _, s := range exist.Comments {
				if strings.HasPrefix(s, flacvorbis.FIELD_TITLE+"=") && title != "" ||
					strings.HasPrefix(s, flacvorbis.FIELD_ALBUM+"=") && album != "" ||
					strings.HasPrefix(s, flacvorbis.FIELD_ARTIST+"=") && len(artists) != 0 {
					continue
				}
				comment.Comments = append(comment.Comments, s)
			}
		}
	}

	// add / replace flac comment
	cmtBlock := comment.Marshal()
	if existCommentIdx < 0 {
		f.Meta = append(f.Meta, &cmtBlock)
	} else {
		f.Meta[existCommentIdx] = &cmtBlock
	}

	if m.AlbumArt != nil {
		coverMime := mime.TypeByExtension(m.AlbumArtExt)
		logger.Debug("cover image mime detect", zap.String("mime", coverMime))
		cover, err := flacpicture.NewFromImageData(
			flacpicture.PictureTypeFrontCover,
			"Front cover",
			m.AlbumArt,
			coverMime,
		)

		if err != nil {
			logger.Warn("failed to create flac cover", zap.Error(err))
		} else {
			coverBlock := cover.Marshal()

			// Add / replace flac cover. Append only when the file has no picture
			// block yet; appending before the lookup would leave a duplicate.
			coverIdx := slices.IndexFunc(f.Meta, func(b *flac.MetaDataBlock) bool {
				return b.Type == flac.Picture
			})
			if coverIdx < 0 {
				f.Meta = append(f.Meta, &coverBlock)
			} else {
				f.Meta[coverIdx] = &coverBlock
			}
		}
	}

	return f.Save(outPath)
}
